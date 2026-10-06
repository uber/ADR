/*
 * ADR's bounded POSIX hook guardian.
 *
 * It has no Python dependency and never parses agent-controlled JSON. It
 * supervises the core, accepts only a closed private decision protocol,
 * and emits the vendor's JSON itself. Missing/stalled/broken core => deny.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int post_tool = 0;
static int prompt_submit = 0;

static double monotonic_seconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (double)now.tv_sec + (double)now.tv_nsec / 1000000000.0;
}

static const char *denial_reason(const char *decision) {
    /* Closed codes only: never interpolate a tool argument or a core-supplied
     * free-form message into the harness's JSON response. */
    if (strcmp(decision, "deny:protected_path") == 0)
        return "ADR blocked access to a protected file or configuration.";
    if (strcmp(decision, "deny:execution_policy") == 0)
        return "ADR's strict execution policy blocks this command or unrecognized tool.";
    if (strcmp(decision, "deny:approval_denied") == 0)
        return "This operation was denied in ADR's approval dialog.";
    if (strcmp(decision, "deny:approval_expired") == 0)
        return "ADR's approval request expired. Retry the operation if it is still needed.";
    if (strcmp(decision, "deny:approval_queue_full") == 0)
        return "ADR's approval queue is full. Finish pending approvals, then retry.";
    if (strcmp(decision, "deny:app_unavailable") == 0)
        return "ADR's approval dialog is unavailable. Open the ADR menu-bar app and retry.";
    if (strcmp(decision, "deny:invalid_request") == 0)
        return "ADR could not validate this tool request; no approval was granted.";
    if (strcmp(decision, "deny:policy_unavailable") == 0)
        return "ADR could not load its local protection policy. Open ADR to check its status.";
    if (strcmp(decision, "deny:safety_timeout") == 0)
        return "ADR's safety check timed out; no approval was granted.";
    if (strcmp(decision, "deny:vault_execution_required") == 0)
        return "Use adr_run_command for saved $VARIABLE credentials. It is built into the ADR plugin; no separate vault setup is needed. Local programs receive the values and the model receives filtered output.";
    if (strcmp(decision, "deny:credential_check_unavailable") == 0)
        return "ADR could not check this tool result against saved credentials. The result was withheld. Open Credential vault in ADR to check storage.";
    if (strcmp(decision, "deny:known_malicious_artifact") == 0)
        return "ADR blocked a known malicious artifact. Review Malicious artifacts in ADR.";
    return NULL;
}

static void emit(const char *harness, const char *decision) {
    if (strcmp(decision, "pass") == 0) {
        puts("{}");
        return;
    }
    int secret = strcmp(decision, "secret") == 0;
    if (prompt_submit) {
        const char *message = secret
            ? "ADR stopped this prompt because it may contain a credential. If it is not already saved, open ADR > Credential vault > Add credential. Replace the value with its $VARIABLE name and submit again. Use adr_run_command for code that needs the variable."
            : "ADR could not check this prompt. Open the ADR menu-bar app and submit again.";
        printf("{\"decision\":\"block\",\"reason\":\"%s\"}\n", message);
        return;
    }
    const char *specific = denial_reason(decision);
    const char *reason = secret
        ? "ADR withheld a possible credential. Open ADR Credential vault to configure safe service access. Use an allowed alias through ADR; never paste the secret into this conversation."
        : specific ? specific
        : post_tool ? "ADR could not finish checking this tool result. The result was withheld."
        : strcmp(decision, "ask") == 0
        ? "ADR requires your approval for this operation."
        : "ADR could not run its local safety check. Open the ADR app and retry.";
    if (post_tool) {
        if (strcmp(harness, "claude") == 0)
            printf("{\"hookSpecificOutput\":{\"hookEventName\":\"PostToolUse\",\"updatedToolOutput\":\"%s\"}}\n", reason);
        else if (strcmp(harness, "codex") == 0)
            printf("{\"decision\":\"block\",\"reason\":\"%s\"}\n", reason);
        else if (strcmp(harness, "opencode") == 0)
            printf("{\"blocked\":true,\"message\":\"%s\"}\n", reason);
        else puts("{}");
        return;
    }
    if (secret || specific || (strcmp(decision, "ask") == 0 && strcmp(harness, "claude") != 0)) decision = "deny";
    int wrapped = strcmp(harness, "claude") == 0 || strcmp(harness, "codex") == 0;
    if (wrapped) printf("{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",");
    else printf("{");
    printf("\"permissionDecision\":\"%s\",\"permissionDecisionReason\":\"%s\"}", decision, reason);
    if (wrapped) printf("}");
    puts("");
}

int main(int argc, char **argv) {
    const char *harness = argc > 1 ? argv[1] : "claude";
    const char *state_dir = argc > 2 ? argv[2] : "";
    post_tool = argc > 3 && strcmp(argv[3], "post") == 0;
    prompt_submit = argc > 3 && strcmp(argv[3], "prompt") == 0;
    if ((strcmp(harness, "claude") != 0 && strcmp(harness, "copilot") != 0
         && strcmp(harness, "codex") != 0 && strcmp(harness, "opencode") != 0)
        || state_dir[0] != '/' || strlen(state_dir) > 8192) {
        emit(harness, "deny"); return 0;
    }
    char path[8256];
    if (snprintf(path, sizeof(path), "%s/bridge-argv.bin", state_dir) >= (int)sizeof(path)) {
        emit(harness, "deny"); return 0;
    }
    int flags = O_RDONLY;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    int fd = open(path, flags);
    struct stat info;
    if (fd < 0 || fstat(fd, &info) != 0 || !S_ISREG(info.st_mode)
        || info.st_uid != getuid() || (info.st_mode & 0077) || info.st_size <= 1 || info.st_size > 16384) {
        if (fd >= 0) close(fd);
        emit(harness, "deny"); return 0;
    }
    char buffer[16385];
    ssize_t count = 0;
    while (count < info.st_size) {
        ssize_t got = read(fd, buffer + count, (size_t)(info.st_size - count));
        if (got <= 0) break;
        count += got;
    }
    close(fd);
    if (count != info.st_size || buffer[count - 1] != '\0' || buffer[0] != '/') {
        emit(harness, "deny"); return 0;
    }
    char *child_argv[32];
    int arguments = 0;
    for (ssize_t index = 0; index < count && arguments < 20;) {
        size_t length = strnlen(buffer + index, (size_t)(count - index));
        if (!length || length >= (size_t)(count - index)) { emit(harness, "deny"); return 0; }
        child_argv[arguments++] = buffer + index;
        index += (ssize_t)length + 1;
        if (index < count && arguments == 20) { emit(harness, "deny"); return 0; }
    }
    child_argv[arguments++] = "hook";
    child_argv[arguments++] = "--harness";
    child_argv[arguments++] = (char *)harness;
    child_argv[arguments++] = "--state-dir";
    child_argv[arguments++] = (char *)state_dir;
    child_argv[arguments++] = "--guard-protocol";
    child_argv[arguments++] = "--phase";
    child_argv[arguments++] = prompt_submit ? "prompt" : post_tool ? "post" : "pre";
    child_argv[arguments] = NULL;

    int descriptors[2];
    if (pipe(descriptors) != 0) { emit(harness, "deny"); return 0; }
    double started = monotonic_seconds();
    if (started < 0) {
        close(descriptors[0]); close(descriptors[1]); emit(harness, "deny"); return 0;
    }
    double deadline = started + 4.0;
    pid_t child = fork();
    if (child == 0) {
        setpgid(0, 0);
        close(descriptors[0]);
        dup2(descriptors[1], STDOUT_FILENO);
        close(descriptors[1]);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
        execv(child_argv[0], child_argv);
        _exit(127);
    }
    close(descriptors[1]);
    if (child < 0) { close(descriptors[0]); emit(harness, "deny"); return 0; }
    setpgid(child, child);
    fcntl(descriptors[0], F_SETFL, O_NONBLOCK);
    char response[64] = {0};
    size_t used = 0;
    int status = 0, exited = 0, eof = 0, invalid = 0, waiting = 0;
    double now;
    while ((now = monotonic_seconds()) >= 0 && now < deadline) {
        struct pollfd polling = { descriptors[0], POLLIN | POLLHUP, 0 };
        poll(&polling, 1, 25);
        if (polling.revents & (POLLIN | POLLHUP)) {
            char incoming[64];
            ssize_t got = read(descriptors[0], incoming, sizeof(incoming));
            if (got > 0) {
                if (used + (size_t)got >= sizeof(response)) { invalid = 1; break; }
                memcpy(response + used, incoming, (size_t)got); used += (size_t)got;
                if (!waiting && !post_tool && !prompt_submit && used >= 8 && memcmp(response, "waiting\n", 8) == 0) {
                    /* Only a checked operation awaiting the owner's native
                     * dialog gets a longer deadline. A stalled core still gets 4s. */
                    waiting = 1;
                    deadline = started + 120.0;
                    memmove(response, response + 8, used - 8);
                    used -= 8;
                    response[used] = '\0';
                }
            } else if (got == 0) eof = 1;
            else if (errno != EAGAIN && errno != EINTR) { invalid = 1; break; }
        }
        if (!exited && waitpid(child, &status, WNOHANG) == child) exited = 1;
        if (exited && eof) break;
    }
    close(descriptors[0]);
    int expired = now >= deadline;
    if (!exited) {
        /* The unreaped child PID cannot have been reused by another process. */
        if (getpgid(child) == child) kill(-child, SIGKILL);
        else kill(child, SIGKILL);
        waitpid(child, &status, 0);
        invalid = 1;
    }
    if (!eof || !WIFEXITED(status) || WEXITSTATUS(status) != 0) invalid = 1;
    if (memchr(response, '\0', used) != NULL) invalid = 1;
    while (used && (response[used - 1] == '\n' || response[used - 1] == '\r')) response[--used] = '\0';
    if (!invalid && (strcmp(response, "pass") == 0 || strcmp(response, "ask") == 0
                    || strcmp(response, "deny") == 0 || strcmp(response, "secret") == 0
                    || denial_reason(response) != NULL))
        emit(harness, response);
    else emit(harness, expired ? (waiting ? "deny:approval_expired" : "deny:safety_timeout") : "deny");
    return 0;
}
