// SPDX-License-Identifier: GPL-2.0

#include "kdfsan_types.h"
#include "kdfsan_shadow.h"
#include "kdfsan_interface.h"

int kdfsan_alloc_page(struct page *page, unsigned int order,
		     gfp_t orig_flags, int node)
{
	struct page *shadow;
	int num_pages = 1 << order;
	int i;

	ENTER_NOINIT_RT(0);

	if (orig_flags & __GFP_NO_KDFSAN_SHADOW) {
		for (i = 0; i < num_pages; i++) {
			(&page[i])->shadow = NULL;
		}
		LEAVE_NOINIT_RT();
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

	LEAVE_NOINIT_RT();
	return 0;
}
EXPORT_SYMBOL(kdfsan_alloc_page);

void kdfsan_free_page(struct page *page, unsigned int order)
{
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

	ENTER_NOINIT_RT();

	shadow = (&page[0])->shadow;

	for (i = 0; i < num_pages; i++) {
		KDF_PANIC_ON((&page[i])->shadow == NULL, "KDFSan error: Page is not backed by a shadow page");
		KDF_PANIC_ON(((&page[i])->shadow)->shadow != NULL, "KDFSan error: Current page's shadow page is backed by another shadow page");
		(&page[i])->shadow = NULL;
	}

	// TODO: should __free_pages be added to kernel's KDFSan ABI list?
	__free_pages(shadow, order);

	LEAVE_NOINIT_RT();
}
EXPORT_SYMBOL(kdfsan_free_page);

void kdfsan_split_page(struct page *page, unsigned int order)
{
	struct page *shadow;

	if ((&page[0])->shadow == NULL)
		return;

	ENTER_NOINIT_RT();

	shadow = (&page[0])->shadow;

	// TODO: should split_page be added to kernel's KDFSan ABI list?
	split_page(shadow, order);

	LEAVE_NOINIT_RT();
}
EXPORT_SYMBOL(kdfsan_split_page);

/*
void kdf_shadow_clear(uptr_t addr, size_t size)
{
	void *shadow_beg;
	void *shadow_end;
	size_t shadow_size;

	shadow_beg = kdf_shadow_get(addr);
	shadow_end = kdf_shadow_get(addr);

	KDF_PANIC_ON(shadow_beg == NULL && shadow_end != NULL, "KDFSan error");
	KDF_PANIC_ON(shadow_beg != NULL && shadow_end == NULL, "KDFSan error");

	if (shadow_beg == NULL && shadow_end == NULL)
		return;

	KDF_PANIC_ON(shadow_beg > shadow_end, "KDFSan error");

	// TODO: I think this is a bug in KTSan, and it should be something like
	// shadow_size = shadow_beg + (size);
	shadow_size = (uptr_t)shadow_end - (uptr_t)shadow_beg;
	memset(shadow_beg, 0, shadow_size);
}
*/
