#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <limits.h>

/* APK payload only. This program does not implement an OTA verification bypass. */
#define MAX_APKS 256
#define MAX_DEPTH 8
static char *files[MAX_APKS];
static size_t count;
static FILE *ui;
static int errors;

static void report(const char *message) {
    fprintf(ui, "ui_print %s\n", message);
    fflush(ui);
}
static int compare(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}
static void scan(const char *root, unsigned depth, int optional) {
    struct stat st;
    if (lstat(root, &st)) {
        if (!(optional && errno == ENOENT)) { report("Cannot inspect APK directory"); errors++; }
        return;
    }
    if (!S_ISDIR(st.st_mode)) { report("APK directory must be a real directory"); errors++; return; }
    if (depth > MAX_DEPTH) { report("APK directory depth exceeded"); errors++; return; }
    DIR *d = opendir(root);
    if (!d) { report("Cannot read APK directory"); errors++; return; }
    struct dirent *e;
    for (;;) {
        errno = 0;
        e = readdir(d);
        if (!e) { if (errno) { report("Directory read failed"); errors++; } break; }
        if (e->d_name[0] == '.') continue;
        char path[PATH_MAX];
        int n = snprintf(path, sizeof(path), "%s/%s", root, e->d_name);
        if (n < 0 || (size_t)n >= sizeof(path)) { report("Path too long"); errors++; continue; }
        if (lstat(path, &st)) { report("Cannot inspect file"); errors++; continue; }
        if (S_ISDIR(st.st_mode)) { scan(path, depth + 1, 0); continue; }
        size_t len = strlen(path);
        if (!S_ISREG(st.st_mode) || len < 4 || strcmp(path + len - 4, ".apk")) continue;
        /* Prevent update UI protocol injection from filenames. No shell is used. */
        if (strchr(path, '\n') || strchr(path, '\r')) { report("Invalid filename"); errors++; continue; }
        if (count == MAX_APKS) { report("Too many APKs"); errors++; continue; }
        files[count] = strdup(path);
        if (!files[count]) { report("Out of memory"); errors++; break; }
        count++;
    }
    closedir(d);
}
static int install_apk(const char *path) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (!pid) {
        execl("/system/bin/pm", "pm", "install", "-r", path, (char *)NULL);
        _exit(127);
    }
    int status;
    while (waitpid(pid, &status, 0) < 0) { if (errno != EINTR) return -1; }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}
int main(int argc, char **argv) {
    int dry = argc == 3 && !strcmp(argv[1], "--dry-run");
    ui = stdout;
    if (!dry) {
        if (argc < 4) { fprintf(stderr, "Usage: %s --dry-run DIRECTORY | API FD PACKAGE [RETRY]\n", argv[0]); return 2; }
        char *end;
        errno = 0;
        long fd = strtol(argv[2], &end, 10);
        if (errno || end == argv[2] || *end || fd < 3 || fd > INT_MAX) return 2;
        /* Keep child package-manager output separate from the update protocol. */
        int copy = dup((int)fd);
        if (copy < 0) return 2;
        ui = fdopen(copy, "w");
        if (!ui) { close(copy); return 2; }
    }
    report(dry ? "X70 installer: dry run" : "X70 installer: APK payload");
    if (dry) scan(argv[2], 0, 0);
    else {
        scan("/storage/udisk/apk", 0, 1);
        scan("/storage/udisk1/apk", 0, 1);
        scan("/storage/udisk2/apk", 0, 1);
    }
    qsort(files, count, sizeof(files[0]), compare);
    if (!count) { report("No APKs found; nothing installed"); errors++; }
    int result = errors ? 1 : 0;
    /* Complete discovery before making changes. */
    if (!errors) for (size_t i = 0; i < count; i++) {
        fprintf(ui, "ui_print %s %s\n", dry ? "Would install" : "Installing", files[i]);
        fflush(ui);
        if (!dry && install_apk(files[i]) != 0) {
            report("APK installation failed; stopping"); result = 1; break;
        }
        fprintf(ui, "set_progress %.6f\n", (double)(i + 1) / (double)count);
        fflush(ui);
    }
    report(result ? "NOT COMPLETED" : dry ? "Dry run complete; no changes made" : "APK installation complete");
    for (size_t i = 0; i < count; i++) free(files[i]);
    if (ui != stdout) fclose(ui);
    return result;
}
