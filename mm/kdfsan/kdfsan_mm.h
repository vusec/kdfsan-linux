// SPDX-License-Identifier: GPL-2.0

#ifndef KDFSAN_MM_H
#define KDFSAN_MM_H

int kdf_alloc_page(struct page *page, unsigned int order, gfp_t orig_flags, int node);
void kdf_free_page(struct page *page, unsigned int order);
void kdf_split_page(struct page *page, unsigned int order);
void kdf_copy_page_shadow(struct page *dst, struct page *src);

#endif // KDFSAN_MM_H
