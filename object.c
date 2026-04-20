// object.c — Content-addressable object store
//
// Every piece of data (file contents, directory listings, commits) is stored
// as an "object" named by its SHA-256 hash. Objects are stored under
// .pes/objects/XX/YYYYYY... where XX is the first two hex characters of the
// hash (directory sharding).
//
// PROVIDED functions: compute_hash, object_path, object_exists, hash_to_hex, hex_to_hash
// TODO functions:     object_write, object_read

#include "pes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

// ─── PROVIDED ────────────────────────────────────────────────────────────────

void hash_to_hex(const ObjectID *id, char *hex_out) {
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(hex_out + i * 2, "%02x", id->hash[i]);
    }
    hex_out[HASH_HEX_SIZE] = '\0';
}

int hex_to_hash(const char *hex, ObjectID *id_out) {
    if (strlen(hex) < HASH_HEX_SIZE) return -1;
    for (int i = 0; i < HASH_SIZE; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        id_out->hash[i] = (uint8_t)byte;
    }
    return 0;
}

void compute_hash(const void *data, size_t len, ObjectID *id_out) {
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, id_out->hash, &hash_len);
    EVP_MD_CTX_free(ctx);
}

// Get the filesystem path where an object should be stored.
// Format: .pes/objects/XX/YYYYYYYY...
// The first 2 hex chars form the shard directory; the rest is the filename.
void object_path(const ObjectID *id, char *path_out, size_t path_size) {
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id, hex);
    snprintf(path_out, path_size, "%s/%.2s/%s", OBJECTS_DIR, hex, hex + 2);
}

int object_exists(const ObjectID *id) {
    char path[512];
    object_path(id, path, sizeof(path));
    return access(path, F_OK) == 0;
}

// ─── TODO: Implement these ──────────────────────────────────────────────────

// Write an object to the store.
//
// Returns 0 on success, -1 on error.
int object_write(ObjectType type, const void *data, size_t len, ObjectID *id_out) {
    // 1. Build the header string: "blob <size>\0"
    const char *type_str = (type == OBJ_BLOB)   ? "blob"   :
                           (type == OBJ_TREE)   ? "tree"   : "commit";
    char header[64];
    int hlen = snprintf(header, sizeof(header), "%s %zu", type_str, len) + 1;
    // +1 includes the null terminator in hlen

    // 2. Combine header + data into one buffer
    size_t total = (size_t)hlen + len;
    uint8_t *full = malloc(total);
    if (!full) return -1;
    memcpy(full, header, hlen);
    memcpy(full + hlen, data, len);

    // 3. Compute SHA-256 of the full buffer using EVP (no deprecated SHA256())
    compute_hash(full, total, id_out);

    // 4. Check for deduplication — already stored, skip writing
    if (object_exists(id_out)) {
        free(full);
        return 0;
    }

    // 5. Build shard directory path: .pes/objects/XX/
    char hex[HASH_HEX_SIZE + 1];
    hash_to_hex(id_out, hex);

    char shard_dir[512];
    snprintf(shard_dir, sizeof(shard_dir), "%s/%.2s", OBJECTS_DIR, hex);
    mkdir(shard_dir, 0755); // ok if already exists

    // 6. Get final object path: .pes/objects/XX/YYYY...
    char path[512];
    object_path(id_out, path, sizeof(path));

    // 7. Write to a temp file in the same shard directory
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);

    int fd = open(tmp_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) { free(full); return -1; }

    ssize_t written = write(fd, full, total);
    free(full);
    if (written != (ssize_t)total) { close(fd); return -1; }

    // 8. fsync to ensure data reaches disk before rename
    fsync(fd);
    close(fd);

    // 9. Atomic rename: temp -> final path
    if (rename(tmp_path, path) != 0) return -1;

    // 10. fsync the shard directory to persist the rename
    int dir_fd = open(shard_dir, O_RDONLY);
    if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
    }

    return 0;
}

// Read an object from the store.
//
// The caller is responsible for calling free(*data_out).
// Returns 0 on success, -1 on error (file not found, corrupt, etc.).
int object_read(const ObjectID *id, ObjectType *type_out,
                void **data_out, size_t *len_out) {
    // 1. Get the file path from the hash
    char path[512];
    object_path(id, path, sizeof(path));

    // 2. Open and read the entire file into memory
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    size_t file_size = (size_t)ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *buf = malloc(file_size);
    if (!buf) { fclose(f); return -1; }

    if (fread(buf, 1, file_size, f) != file_size) {
        fclose(f); free(buf); return -1;
    }
    fclose(f);

    // 3. Verify integrity: recompute SHA-256 and compare to the expected hash
    ObjectID computed;
    compute_hash(buf, file_size, &computed);
    if (memcmp(computed.hash, id->hash, HASH_SIZE) != 0) {
        free(buf);
        return -1; // Data is corrupted
    }

    // 4. Find the null byte separating header from data
    uint8_t *null_pos = memchr(buf, '\0', file_size);
    if (!null_pos) { free(buf); return -1; }

    // 5. Parse the type string from the header
    if      (strncmp((char*)buf, "blob ",   5) == 0) *type_out = OBJ_BLOB;
    else if (strncmp((char*)buf, "tree ",   5) == 0) *type_out = OBJ_TREE;
    else if (strncmp((char*)buf, "commit ", 7) == 0) *type_out = OBJ_COMMIT;
    else { free(buf); return -1; }

    // 6. Extract the data portion (everything after the null byte)
    uint8_t *data_start = null_pos + 1;
    size_t data_len = file_size - (size_t)(data_start - buf);

    *data_out = malloc(data_len + 1);   // +1 for safe null terminator
    if (!*data_out) { free(buf); return -1; }

    memcpy(*data_out, data_start, data_len);
    ((uint8_t *)*data_out)[data_len] = '\0';
    *len_out = data_len;

    free(buf);
    return 0;
}
