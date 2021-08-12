#include "kdfsan_types.h"

int kdf_alloc_page(struct page *page, unsigned int order, gfp_t orig_flags, int node) {
  struct page *shadow;
  int num_pages = 1 << order;
  int i;

  if (orig_flags & __GFP_NO_KDFSAN_SHADOW) {
    for (i = 0; i < num_pages; i++) {
      (&page[i])->shadow = NULL;
    }
    return 0;
  }

  gfp_t new_flags = GFP_ATOMIC | __GFP_ZERO | __GFP_NO_KDFSAN_SHADOW;
  shadow = alloc_pages_node(node, new_flags, order);
  KDF_PANIC_ON(shadow == NULL, "KDFSan error: alloc_pages_node returned a NULL shadow page");

  //printk("kdfsan_alloc_page(page=%px,order=%02d,flags=0x%08x,node=%d): mem=%px; shadow=%px\n",
  //    page,order,flags,node,page_address(page),page_address(shadow));

  for (i = 0; i < num_pages; i++) {
    (&page[i])->shadow = &shadow[i];
    ((&page[i])->shadow)->shadow = NULL;
  }

  return 0;
}

void kdf_free_page(struct page *page, unsigned int order) {
  struct page *shadow;
  int num_pages = 1 << order;
  int i;

  // Checking if these pages are shadow pages, and if so, return early
  if ((&page[0])->shadow == NULL) {
    for (i = 0; i < num_pages; i++) {
      KDF_PANIC_ON((&page[i])->shadow != NULL, "KDFSan error: Shadow page is backed by a shadow page");
    }
    return;
  }

  shadow = (&page[0])->shadow;

  for (i = 0; i < num_pages; i++) {
    KDF_PANIC_ON((&page[i])->shadow == NULL, "KDFSan error: Page is not backed by a shadow page");
    KDF_PANIC_ON(((&page[i])->shadow)->shadow != NULL, "KDFSan error: Current page's shadow page is backed by another shadow page");
    (&page[i])->shadow = NULL;
  }

  __free_pages(shadow, order);
}

void kdf_split_page(struct page *page, unsigned int order) {
  struct page *shadow;
  if ((&page[0])->shadow == NULL) return;
  shadow = (&page[0])->shadow;
  split_page(shadow, order);
}