#include "kdfsan_types.h"
#include "kdfsan_internal.h"
#include "kdfsan_shadow.h"

/**** Helpers: data ****/

static const uptr DESC_LEN = 150UL;
typedef struct {
  u8 b[NUM_LABELS]; // this represents one bit as an 8-bit word; obviously not efficient
  char desc[DESC_LEN];
} dfsan_label_bitvector;

typedef struct {
  dfsan_label last_label;
  dfsan_label_bitvector bitvectors[NUM_LABELS];
} dfsan_label_list;
static dfsan_label_list* label_list = NULL;

// TODO: These should probably have mutexes...
static u8* b_tmp_kdf_union = NULL;
static char* str_kdf_print_bitvector = NULL;

// An actual label within label_list (i.e., not just "NUM_LABELS - 1") to be returned when attempting to create a new label when no more labels are available
static dfsan_label max_label = -1;

/**** Helpers: util ****/

static void kdf_print_bitvector(dfsan_label lbl) {
  KDF_CHECK_LABEL(lbl);
  u8 *b = label_list->bitvectors[lbl].b;

  //char str[NUM_LABELS + 1] = {0}; // +1 for all labels + NULL terminator
  __memset(str_kdf_print_bitvector,0,NUM_LABELS + 1);

  for(int i = 0; i <= label_list->last_label; i++) {
    KDF_PANIC_ON(b[i] != 0 && b[i] != 1, "bitvector values should only be 0 or 1");
    str_kdf_print_bitvector[i] = b[i] + 48; // Can't call sprintf or itoa, so +48 will have to do (0+48='0' and 1+48='1')
  }
  printk("label %d = [%s...], (%s)\n", lbl, str_kdf_print_bitvector, label_list->bitvectors[lbl].desc);
}

// Note: If b is NULL then a new label is created with a single unique bit set
static dfsan_label kdf_create_next_label(u8 *b, const char *desc) {
  // Check whether we can create a new label
  if(label_list->last_label + 1 >= NUM_LABELS) {
    //printk("KDFSan ERROR: out of labels; assigning 'max-label' label\n");
    return max_label;
  }
  label_list->last_label++;
  //printk("KDFSan: last_label increased to %d",label_list->last_label);

  // Check whether a bitvector was supplied
  dfsan_label this_label = label_list->last_label;
  dfsan_label_bitvector * this_bitvector = &label_list->bitvectors[this_label];
  if(b == NULL) {
    // If bitvector was not supplied, create one with a single unique bit set in label_list
    this_bitvector->b[this_label] = 1;
  }
  else {
    // If bitvector was supplied, copy it into label_list
    __memcpy(this_bitvector->b, b, NUM_LABELS); // size could probably just be this_label; that'd be slightly faster
  }
  kdf_util_strlcpy(this_bitvector->desc, desc, DESC_LEN);

  return this_label;
}

/**** Helpers: init ****/

void kdf_init_internal_data(void) {
  size_t size = sizeof(dfsan_label_list);
  printk("kdf_alloc_label_list: allocating label_list of size %zu\n", size);
  label_list = kzalloc(size, GFP_KERNEL);

  b_tmp_kdf_union = kzalloc(sizeof(u8) * NUM_LABELS, GFP_KERNEL);
  str_kdf_print_bitvector = kzalloc(sizeof(char) * (NUM_LABELS + 1), GFP_KERNEL);

  // Initialize 0 label: b should already be set to all 0; last_label should already by 0
  KDF_PANIC_ON(label_list->last_label != 0, "KDFSan error: the last_label should be 0 after label_list is initialized");
  kdf_util_strlcpy(label_list->bitvectors[0].desc, "no-taint", DESC_LEN);
  #ifdef DEBUG_KDF_RT
  kdf_print_bitvector(0);
  #endif

  max_label = kdf_create_label("max-label");
}

/**** Interfaces handlers ****/

void kdf_memtransfer(void *dest, const void *src, uptr count) {
  u8 *tmp;
  const u8 *s;
  if (dest <= src) {
    tmp = dest;
    s = src;
    while (count--) kdf_set_shadow(tmp++, kdf_get_shadow(s++));
  } else {
    tmp = dest;
    tmp += count;
    s = src;
    s += count;
    while (count--) kdf_set_shadow(--tmp, kdf_get_shadow(--s));
  }
}

void kdf_set_label(dfsan_label label, void *addr, uptr size) {
  for (u8* datap = (u8*) addr; size != 0; --size, ++datap) {
    dfsan_label this_label = kdf_get_shadow(datap);
    if (label != this_label) {
      kdf_set_shadow(datap, label);
    }
  }
}

dfsan_label kdf_union(dfsan_label l1, dfsan_label l2) {
  // possible fast paths
  if (l1 == 0) return l2;
  if (l2 == 0) return l1;
  if (l1 == l2) return l1;

  //u8 b_tmp[NUM_LABELS] = {0};
  __memset(b_tmp_kdf_union,0,NUM_LABELS);

  KDF_CHECK_LABEL(l1);
  KDF_CHECK_LABEL(l2);

  // get l1's and l2's bitvectors
  dfsan_label_bitvector * b1 = &label_list->bitvectors[l1];
  dfsan_label_bitvector * b2 = &label_list->bitvectors[l2];

  // bitwise or the bitvectors
  for(int i_bit = 0; i_bit <= label_list->last_label; i_bit++) {
    b_tmp_kdf_union[i_bit] = b1->b[i_bit] | b2->b[i_bit];
    KDF_PANIC_ON(b_tmp_kdf_union[i_bit] != 0 && b_tmp_kdf_union[i_bit] != 1, "kdf_union error: bitvector values should only be 0 or 1");
  }

  // check if the resulting bitvector exists
  // TODO: it might be faster to iterate from last_label to 0, assuming labels are most commonly union'ed with recently created labels
  for(dfsan_label lbl = 0; lbl <= label_list->last_label; lbl++) {
    if(kdf_util_memcmp(b_tmp_kdf_union, label_list->bitvectors[lbl].b, label_list->last_label + 1) == 0) {
      // if resulting bitvector exists, return its label
      return lbl;
    }
  }

  // otherwise, if resulting bitvector does not exist, insert it with a new label
  dfsan_label new_lbl = kdf_create_next_label(b_tmp_kdf_union, "created-by-kdf_union");
  #ifdef DEBUG_KDF_RT
  kdf_print_bitvector(new_lbl);
  #endif

  return new_lbl;
}

dfsan_label kdf_read_label(const void *addr, uptr n) {
  dfsan_label ret_label = 0;
  for (u8* datap = (u8*) addr; n != 0; --n, ++datap) {
    dfsan_label next_label = kdf_get_shadow(datap);
    if (ret_label != next_label) {
      ret_label = kdf_union(ret_label, next_label);
    }
  }
  return ret_label;
}

void kdf_add_label(dfsan_label label_src, void *addr, uptr size) {
  for (u8* datap = (u8*) addr; size != 0; --size, ++datap) {
    dfsan_label label_tmp = kdf_get_shadow(datap);
    if (label_tmp != label_src) {
      dfsan_label label_dst = kdf_union(label_tmp, label_src);
      kdf_set_shadow(datap, label_dst);
    }
  }
}

dfsan_label kdf_create_label(const char *desc) {
  dfsan_label lbl = kdf_create_next_label(NULL, desc);
  #ifdef DEBUG_KDF_RT
  kdf_print_bitvector(lbl);
  #endif
  return lbl;
}

int kdf_has_label(dfsan_label haver, dfsan_label havee) {
  u8 *b_haver = label_list->bitvectors[haver].b;
  u8 *b_havee = label_list->bitvectors[havee].b;
  for(int i = 0; i <= label_list->last_label; i++) {
    if(b_havee[i] == 1 && b_haver[i] != 1) {
      return false;
    }
  }
  return true;
}

// If the given label label contains a label with the description desc, returns that label, else returns 0
dfsan_label kdf_has_label_with_desc(dfsan_label label, const char *desc) {
  // For each label with a matching description
  for(dfsan_label this_lbl = 0; this_lbl <= label_list->last_label; this_lbl++) {
    dfsan_label_bitvector *this_bitvector = &label_list->bitvectors[this_lbl];
    if(kdf_util_strcmp(this_bitvector->desc, desc) == 0) {
      // Check whether given label contains it, and if so, return
      if(kdf_has_label(label, this_lbl) == true) {
        return this_lbl;
      }
    }
  }
  return 0;
}

dfsan_label kdf_get_label_count(void) {
  return label_list->last_label;
}

/**** Misc. internals ****/

void kdf_copy_label_info(dfsan_label label, char * dest, size_t count) {
  u8 *b = label_list->bitvectors[label].b;
  bool first_report = true;
  __memset(dest, 0, count);
  CONCAT_STR("label ", dest, count); CONCAT_NUM(label, 10, dest, count); CONCAT_STR(": {", dest, count);
  for(dfsan_label i = 0; i <= label_list->last_label; i++) {
    KDF_PANIC_ON(b[i] != 0 && b[i] != 1, "kdf_print_label_info error: bitvector values should only be 0 or 1");
    if(b[i] == 1) {
      if(!first_report) { CONCAT_STR(", ", dest, count); }
      CONCAT_STR("(label: ", dest, count); CONCAT_NUM(i, 10, dest, count);
      CONCAT_STR(", desc: '", dest, count); CONCAT_STR(label_list->bitvectors[i].desc, dest, count);
      CONCAT_STR("')", dest, count);
      first_report = false;
    }
  }
  CONCAT_STR("}", dest, count);
  KDF_PANIC_ON(first_report && label != 0, "kdf_copy_label_info error: a non-zero label should be composed of at least one bit");
}
