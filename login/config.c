// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <alloca.h>
#include <glib.h>
#include <string.h>

#include "ui.h"

static int add_option(glome_public_key_t* t, const char* key, const char* val) {
  if (!strcmp(key, "service-key-id")) {
    t->service_key_id = atoi(val);
  } else if (!strcmp(key, "url-prefix")) {
    size_t len = strlen(val);
    if (len >= 256) { // TODO: use constant
      return -1;
      memcpy(t->url_prefix, val, len+1);
    }
  } else {
    fprintf(stderr, "ignoring option key=%s, val=%s\n", key, val);
  }
  return 0;
}

// Allocates memory into key.
int glome_parse_public_key(glome_public_key_t** key, char* line) {
  *key = calloc(1, sizeof(glome_public_key_t));

  char* state = NULL;
  char* next = strtok_r(line, " ", &state);
  char* delim;
  // Looking for options
  while (next && (delim = strchr(next, '='))) {
    // TODO: deal with option
    fprintf(stderr, "option: %s\n", next); 
    *delim = '\0';
    if (add_option(*key, next, delim+1) < 0) {
      return -1;
    };
    next = strtok_r(NULL, " ", &state);
    // TODO: if null return
  }
  // Done with options, next token is ID.
  if (strcmp(next, "glome-x25519-sha256")) {
    return -1;
  }
  next = strtok_r(NULL, " ", &state);
  // TODO: check null
  // Next token is base64 public key.
  // TODO: decode 

  fprintf(stderr, "public key: %s\n", next);
  // (*key)->key = {0};
  // key
  // service_key_id
  // url_prefix
  return 0;
}

int glome_login_parse_config_file(glome_login_config_t* config) {
  // TODO: check if this is still needed
  bool required = config->config_path != NULL;
  if (!required) {
    config->config_path = DEFAULT_CONFIG_FILE;
  }

  // open file
  FILE* f = fopen(config->config_path, "r");
  // TODO: deal with 'required'

  char linebuf[4096];

  size_t buf_nmem = 2;
  config->server_keys = calloc(buf_nmem, sizeof (glome_public_key_t*));

  size_t i = 0;
  glome_public_key_t** tmp = NULL;
  while (fgets(linebuf, 4096, f)) {
    // TODO: check that the line is not truncated!
    if (linebuf[0] == '#') {
      continue;
    }

    if (glome_parse_public_key(config->server_keys+i, linebuf) < 0) {
      fprintf(stderr, "oh snap\n");
    }
    i++;
    if (i >= buf_nmem) {
      buf_nmem *= 2;
      tmp = realloc(config->server_keys, buf_nmem * sizeof (glome_public_key_t*));
      if (tmp == NULL) {
        free(config->server_keys);
        return -1;
      }
      config->server_keys = tmp;
    }
  }
  config->server_keys[i] = NULL;

  return 0;
}
