#include "my_vm.h"

//physical memory
char *physical_memory = NULL;

int num_bits_pa = 0, //number of bits to represent physical address
	num_bits_va = 0, //number of bits to represent virtual address
	num_bits_po = 0; //number of bits to represent page offset

int num_physical_pages, num_virtual_pages;

int physical_frame_bits = 0, //number of bits to represent physical frame
	page_frame_bits = 0,      //number of bits to represent virtual frame
	page_directory_bits = 0; //number of bits to represent page directory index

int page_offset_mask = 0, //hex mask to find page offset bits in address
	page_table_index_mask = 0, //hex mask to find page table index in address
	physical_frame_mask = 0; //hex mask to find physical frame in pte

//mutex for synchronization
pthread_mutex_t memory_lock;

//tlb cache
struct tlb *tlb_store = NULL;

//tlb variables
int num_bits_tlb_id = 0,
    num_bits_tlb_tag = 0;

//tlb mask
int tlb_id_mask = 0,
    tlb_tag_mask = 0;

//bit vectors for physical and virtual memory
unsigned char *physical_bitmap = NULL,
     *virtual_bitmap = NULL;

//pgdir pointer
pde_t *pgdir = NULL;

int find_num_bits_to_rep(unsigned long long x) {

	int b=0;
	while(x>1) {

		x=x/2;
		b++;
	}
	return b;
}

//function to get mask
int get_mask_for_numbits(int b) {

	int mask = 0;
	mask = ((int)pow(2,b)) - 1;
	return mask;
}

/*
Function responsible for allocating and setting your physical memory 
*/
void set_physical_mem() {

	//Allocate physical memory using mmap or malloc; this is the total size of
	//your memory you are simulating
	physical_memory = (char *)malloc(MEMSIZE);
	//not needed as we initialize page table pages
	//memset(physical_memory,0,MEMSIZE);

	//HINT: Also calculate the number of physical and virtual pages and allocate
	//virtual and physical bitmaps and initialize them
	num_physical_pages = MEMSIZE/PGSIZE;
	num_virtual_pages = MAX_MEMSIZE/PGSIZE;

	num_bits_pa = find_num_bits_to_rep(MEMSIZE);
	num_bits_va = find_num_bits_to_rep(MAX_MEMSIZE);
	num_bits_po = find_num_bits_to_rep(PGSIZE);

	physical_frame_bits = num_bits_pa - num_bits_po;
	page_directory_bits = find_num_bits_to_rep((num_virtual_pages * sizeof(pte_t))/PGSIZE);
	page_frame_bits = num_bits_va - num_bits_po - page_directory_bits;

	page_offset_mask = get_mask_for_numbits(num_bits_po);
	page_table_index_mask = get_mask_for_numbits(page_frame_bits);
	physical_frame_mask = get_mask_for_numbits(physical_frame_bits);

	physical_bitmap = (char *)malloc(num_physical_pages/8);
	virtual_bitmap = (char *)malloc(num_virtual_pages/8);

	memset(physical_bitmap,0,num_physical_pages/8);

	memset(virtual_bitmap,0,num_virtual_pages/8);

	//tlb initialization
	tlb_store = (struct tlb *)malloc(sizeof(struct tlb) * TLB_ENTRIES);

	//tlb number of bits calculation
	num_bits_tlb_id  = find_num_bits_to_rep(TLB_ENTRIES);
	num_bits_tlb_tag = num_bits_va - num_bits_po - num_bits_tlb_id;

	//tlb mask calculation
	tlb_id_mask  = get_mask_for_numbits(num_bits_tlb_id);
	tlb_tag_mask = get_mask_for_numbits(num_bits_tlb_tag);

	//mutex initialization
	pthread_mutex_init(&memory_lock,NULL);
}


/*
Function to free address in bitmap
*/
void free_address_in_bitmap(unsigned long addr,char *bitmap,int bitmap_size) {

	unsigned long target_address = (unsigned long)addr;
	int bitmap_index = (int)target_address/8;
	int bit_in_index = (int)target_address%8;
	int shift = 7 - bit_in_index;
	bitmap[bitmap_index] &= ~(1 << shift);
}

void free_allocated_contiguous_pages(unsigned long start_addr, unsigned long end_addr, char *bitmap, int bitmap_size) {

	while(start_addr <= end_addr) {

		free_address_in_bitmap(start_addr, bitmap, bitmap_size);
		start_addr++;
	}
}

/*
Function to get single free page from bitmap
*/
unsigned long get_single_freepage_from_bitmap(char* bitmap,int bitmap_size,int start_index,int start_bit,int *done) {

	int i;
	*done = 0;
	int done_for_first_byte = 0;
	unsigned long addr;
	i=start_index;
	for(;i<bitmap_size;i++) {

		//check if any bit is 0
		//0 means free
		if(bitmap[i]!=0xff) {

			//find first free(0) bit
			int first_free_page = -1;
			int j = 7;

			if(done_for_first_byte == 0)
				j = 7 - start_bit;

			for(;j>=0;j--) {

	    		if(((bitmap[i]>>j)&0x01) == 0)
		    		first_free_page = 7 - j;

				if(first_free_page != -1)
					break;
		}
		done_for_first_byte = 1;

		if(first_free_page != -1) {

			//we have a free bit in current byte
			//mark as used
			bitmap[i] |= (1<<j);
			//calculate address
			addr = (i*8) + first_free_page;

			*done = 1;
		}
	}

	if(*done == 1)
		break;
	}

	return addr;
}

/*Function that gets the next available page
*/
unsigned long get_next_avail(int num_pages,int *done) {

	//Use virtual address bitmap to find the next free page
	unsigned long virt_addr;
	*done = 0;

	int allocated_pages = 0;
	unsigned long current_allocated, last_allocated;
	int first_time = 0;
	int start_index = 0, start_bit = 0;

	while(allocated_pages < num_pages) {

		current_allocated = get_single_freepage_from_bitmap(virtual_bitmap, num_virtual_pages,start_index,start_bit,done);
		if(*done == 0) {//failed in allocation

			if(allocated_pages > 0)
				free_allocated_contiguous_pages(virt_addr, last_allocated, virtual_bitmap, num_virtual_pages);
			break;
		}

		if(first_time == 0 || (current_allocated - last_allocated != 1)) {

			if(first_time != 0)
				free_allocated_contiguous_pages(virt_addr, last_allocated, virtual_bitmap, num_virtual_pages);
			virt_addr = current_allocated;
			allocated_pages = 1;
		}
		else
			allocated_pages++;

		first_time = 1;
		last_allocated = current_allocated;
		start_index = current_allocated / 8;
		start_bit = current_allocated % 8;
	}

	return virt_addr;
}


/*
Function for getting next physical free page
*/
unsigned long get_next_free_physical_memory(int num_pages,int *done) {

	//use physical memory map to get next free page
	unsigned long phys_addr;
	*done = 0;

	int allocated_pages = 0;
	unsigned long current_allocated, last_allocated;
	int first_time = 0;
	int start_index = 0, start_bit = 0;

	while(allocated_pages < num_pages) {

		current_allocated = get_single_freepage_from_bitmap(physical_bitmap, num_physical_pages,start_index,start_bit,done);
		if(*done == 0) {//failed in allocation

			if(allocated_pages > 0)
				free_allocated_contiguous_pages(phys_addr, last_allocated, physical_bitmap, num_physical_pages);

			break;
		}

		if(first_time == 0 || (current_allocated - last_allocated != 1)) {

			if(first_time != 0)
				free_allocated_contiguous_pages(phys_addr, last_allocated, physical_bitmap, num_physical_pages);
			phys_addr = current_allocated;
			allocated_pages = 1;
		}
		else
			allocated_pages++;

		last_allocated = current_allocated;
		start_index = current_allocated / 8;
		start_bit = current_allocated % 8;
	}

	return phys_addr;
}


/*
 * Part 2: Add a virtual to physical page translation to the TLB.
 * Feel free to extend the function arguments or return type.
 */
int
add_TLB(void *va, void *pa) {

	/*Part 2 HINT: Add a virtual to physical page translation to the TLB */
	unsigned long vaddr = (unsigned long)va;
	vaddr = vaddr >> num_bits_po;

	unsigned long tag,id;
	tag = vaddr & tlb_tag_mask;
	vaddr = vaddr >> num_bits_tlb_tag;
	id = vaddr & tlb_id_mask;

	unsigned long paddr = (unsigned long)pa;
	paddr = paddr >> num_bits_po;
	unsigned long physical_frame = paddr & physical_frame_mask;

	//pte to store in TLB cache
	pte_t pte_to_store = 0;
	//making it valid
	pte_to_store |= (1 << 31);
	pte_to_store |= physical_frame;

	//fetch tlb entry
	//init
	tlb_store[id].valid_and_tag = 0;
	//make it valid
	tlb_store[id].valid_and_tag |= (1 << 31);
	//store tag
	tlb_store[id].valid_and_tag |= tag;
	//store pte
	tlb_store[id].page_table_entry = pte_to_store;

	return 0;
}


//variables to track tlb miss rate
int tlb_total_req = 0,
    tlb_miss = 0;

/*
 * Part 2: Check TLB for a valid translation.
 * Returns the physical page address.
 * Feel free to extend this function and change the return type.
 */
pte_t *
check_TLB(void *va) {

	/* Part 2: TLB lookup code here */
	//count total number of requests
	tlb_total_req++;
	//pte to return
	pte_t *ret_pte = NULL;

	unsigned long vaddr = (unsigned long)va;
	vaddr = vaddr >> num_bits_po;

	unsigned long id,tag;
	tag = vaddr & tlb_tag_mask;
	vaddr = vaddr >> num_bits_tlb_tag;
	id = vaddr & tlb_id_mask;

	//fetch tlb entry and check
	if(((tlb_store[id].valid_and_tag >> 31) & 1) == 1) {

		//tlb entry is valid
		unsigned long stored_tag = tlb_store[id].valid_and_tag & tlb_tag_mask;
		if(tag == stored_tag) { //tlb hit

			ret_pte = (pte_t *)malloc(sizeof(pte_t));
			*ret_pte = tlb_store[id].page_table_entry;
		}
	}

	if(ret_pte == NULL)
		tlb_miss++;//count tlb miss

	return ret_pte;
}


/*
 * Part 2: Print TLB miss rate.
 * Feel free to extend the function arguments or return type.
 */
void
print_TLB_missrate() {

	double miss_rate = 0;

	/*Part 2 Code here to calculate and print the TLB miss rate*/

	miss_rate = ((double)tlb_miss / (double)tlb_total_req) * 100;

	fprintf(stderr, "TLB miss rate %lf\n", miss_rate);
}



/*
Function to check if pte_t is valid
*/
int is_pte_valid(pte_t pte) {

	return pte >> 31;
}

/*
Function to get physical address from page table entry
*/
unsigned long get_physical_address_from_pte_t(pte_t pte, unsigned long page_offset) {

	unsigned long ret_addr = 0;
	ret_addr |= (pte & physical_frame_mask) << num_bits_po;
	ret_addr |= page_offset;
	return ret_addr;
}

/*
Function to check if pde_t is valid
*/
int is_pde_valid(pde_t pde) {

	return pde >> 31;
}

/*
Function to get page address of page table from page directory entry 
*/
unsigned long get_page_address_from_pde_t(pde_t pde, unsigned long page_table_index) {

	unsigned long ret_addr;
	ret_addr = 0;
	ret_addr |= pde & physical_frame_mask;
	ret_addr = ret_addr << num_bits_po;
	ret_addr |= page_table_index << find_num_bits_to_rep(sizeof(pte_t));
	return ret_addr;
}

/*
Function to lookup page directory
*/
pde_t page_directory_lookup(pde_t *pgdir, unsigned long pg_index) {

	return pgdir[pg_index];
}

/*
The function takes a virtual address and page directories starting address and
performs translation to return the physical address
*/
pte_t *translate(pde_t *pgdir, void *va) {

	/* Part 1 HINT: Get the Page directory index (1st level) Then get the
	* 2nd-level-page table index using the virtual address.  Using the page
	* directory index and page table index get the physical address.
	*
	* Part 2 HINT: Check the TLB before performing the translation. If
	* translation exists, then you can return physical address from the TLB.
	*/
	pte_t *pte_from_tlb = check_TLB(va);
	if(pte_from_tlb != NULL) {

		//found in tlb
		return pte_from_tlb;
	}

	unsigned long vaddr;
	vaddr = (unsigned long)va;

	unsigned long page_table_index, page_directory_index, page_offset;

	page_offset = vaddr & page_offset_mask;
	vaddr = vaddr >> num_bits_po;
	page_table_index = vaddr & page_table_index_mask;
	vaddr = vaddr >> page_frame_bits;
	page_directory_index = vaddr & page_directory_bits;

	//fetch page directory entry
	pde_t curr_pde = page_directory_lookup(pgdir,page_directory_index);

	//check if pde is valid
	if(!is_pde_valid(curr_pde)) {

		//pde is not valid
		//return failure status
		printf("pde is invalid\n");
		return NULL;
	}

	//pde is valid
	//so get page table address
	pte_t *ret_pgtable = (pte_t*)malloc(sizeof(pte_t));
	unsigned long pt_address = get_page_address_from_pde_t(curr_pde,page_table_index);
	memcpy(ret_pgtable,physical_memory+pt_address,sizeof(pte_t));

	if(is_pte_valid(*ret_pgtable)) {

		//pte valid and not found in tlb
		//so adding in tlb
		unsigned long paddr = ((*ret_pgtable) & physical_frame_mask) << num_bits_po;
		add_TLB(va,(void *)paddr);
	}

	return ret_pgtable;
}


/*
Function to initialize a page of page table (freshly allocated)
*/
void initialize_page_table_page(pde_t pde) {

	int i;
	for(i=0;i<page_table_index_mask+1;i++) {

		unsigned long page_table_address = get_page_address_from_pde_t(pde,i);
		//fetching pte from the above obtained address
		pte_t curr_pt;
		memcpy(&curr_pt,physical_memory+page_table_address,sizeof(pte_t));

		//making it invalid
		curr_pt &= ~(1 << 31);

		//writing back to memory
		memcpy(physical_memory+page_table_address,&curr_pt,sizeof(pte_t));
    }
}


/*
The function takes a page directory address, virtual address, physical address
as an argument, and sets a page table entry. This function will walk the page
directory to see if there is an existing mapping for a virtual address. If the
virtual address is not present, then a new entry will be added
*/
int
page_map(pde_t *pgdir, void *va, void *pa) {

	/*HINT: Similar to translate(), find the page directory (1st level)
	and page table (2nd-level) indices. If no mapping exists, set the
	virtual to physical mapping */

	unsigned long vaddr, paddr;
	vaddr = (unsigned long)va;
	paddr = (unsigned long)pa;

	unsigned long page_table_index, page_directory_index, physical_frame;

	vaddr = vaddr >> num_bits_po;
	paddr = paddr >> num_bits_po;

	//extract different parts of va and pa
	page_table_index = vaddr & page_table_index_mask;
	vaddr = vaddr >> page_frame_bits;
	page_directory_index = vaddr & page_directory_bits;
	physical_frame = paddr & physical_frame_mask;

	//check if page directory entry is valid
	if(!is_pde_valid(pgdir[page_directory_index])) {

		//printf("page directory entry not valid during page map\n");
		//pde is not valid

		//variable to hold error
		int error;

		//fetch a free page and map it in page directory
		unsigned long page_addr = get_next_free_physical_memory(1,&error);
		if(error == 0) {

			printf("cannot allocate page for page table\n");
			//return failure response as not enough memory for page table
			return -2;
		}

		pgdir[page_directory_index] = 0;
		pgdir[page_directory_index] |= (1 << 31);
		pgdir[page_directory_index] |= page_addr & physical_frame_mask;
		initialize_page_table_page(pgdir[page_directory_index]);
	}

	//fetching pte address from the page directory
	unsigned long page_table_address = get_page_address_from_pde_t(pgdir[page_directory_index],page_table_index);

	//fetching pte from the above obtained address
	pte_t curr_pt;
	memcpy(&curr_pt,physical_memory+page_table_address,sizeof(pte_t));

	//check if pte is valid
	if(!is_pte_valid(curr_pt)) {

		//printf("page table entry not valid\n");
		//pte is not valid
		//set as valid
		curr_pt |= (1 << 31);
		//set physical frame
		curr_pt |= physical_frame;

		//write pte back to physical memory
		memcpy(physical_memory+page_table_address,&curr_pt,sizeof(pte_t));

		//add to tlb
		add_TLB(va,pa);

		//return success response
		return 1;
	}

	//return failure response as already mapped
	return -1;
}


/* Function responsible for allocating pages
and used by the benchmark
*/
void *a_malloc(unsigned int num_bytes) {

	/* 
	* HINT: If the physical memory is not yet initialized, then allocate and initialize.
	*/

	//lock mutex
	pthread_mutex_lock(&memory_lock);

	if(physical_memory == NULL)
		set_physical_mem();

	/* 
	* HINT: If the page directory is not initialized, then initialize the
	* page directory. Next, using get_next_avail(), check if there are free pages. If
	* free pages are available, set the bitmaps and map a new page. Note, you will 
	* have to mark which physical pages are used. 
	*/ 
	int num_pages_needed = num_bytes/PGSIZE + 1;

	//variables to store error
	int error1, error2;

	unsigned long paddr = get_next_free_physical_memory(num_pages_needed,&error1);
	unsigned long vaddr = get_next_avail(num_pages_needed,&error2);

	if(error1 == 1 && error2 == 1) {

		paddr = paddr << num_bits_po;
		vaddr = vaddr << num_bits_po;

		if(pgdir == NULL) {

			int num_pde_entries = (int)pow(2,page_directory_bits);
			pgdir = (pde_t*)malloc(num_pde_entries*sizeof(pde_t));

			int i;
			for(i=0;i<num_pde_entries;i++)
				pgdir[i] = 0;
	    }

		unsigned long cur_vaddr, cur_paddr;
		cur_vaddr = vaddr;
		cur_paddr = paddr;

		while(num_pages_needed > 0) {

			if(page_map(pgdir, (void *)cur_vaddr, (void *)cur_paddr) == -1) {

				printf("cannot map page\n");
				return NULL;
			}
			num_pages_needed--;
			cur_vaddr += (1 << num_bits_po);
			cur_paddr += (1 << num_bits_po);
		}
	}

	//unlock mutex
	pthread_mutex_unlock(&memory_lock);	

	return (void *)vaddr;
}


/*
Function to check if pde_t is valid
*/
int check_pde_valid(pde_t pde) {

	int i;
	for(i=0;i<page_table_index_mask+1;i++) {

		unsigned long page_table_address = get_page_address_from_pde_t(pde,i);
		//fetching pte from the above obtained address
		pte_t curr_pt;
		memcpy(&curr_pt,physical_memory+page_table_address,sizeof(pte_t));
		if(is_pte_valid(curr_pt) == 1)
			return 1;//current pte is valid
	}
	return 0;//return all pte invalid
}


/*
Function to  unmap page
*/
int page_unmap(pde_t *pgdir, void *va) {

	unsigned long vaddr;
	vaddr = (unsigned long)va;

	unsigned long page_table_index, page_directory_index, physical_frame;

	vaddr = vaddr >> num_bits_po;

	//extract different parts of va and pa
	page_table_index = vaddr & page_table_index_mask;
	vaddr = vaddr >> page_frame_bits;
	page_directory_index = vaddr & page_directory_bits;

	//check if page directory entry is valid
	if(!is_pde_valid(pgdir[page_directory_index])) {

		printf("page directory entry not valid\n");
		//return failure response
		return -1;
	}

	//fetching pte address from the page directory
	unsigned long page_table_address = get_page_address_from_pde_t(pgdir[page_directory_index],page_table_index);

	//fetching pte from the above obtained address
	pte_t curr_pt;
	memcpy(&curr_pt,physical_memory+page_table_address,sizeof(pte_t));

	//check if pte is valid
	if(!is_pte_valid(curr_pt)) {

		printf("page table entry not valid\n");
		//return failure response
		return -1;
	}

	//pte is valid, so unmapping
	//fetch physical frame address
	unsigned long paddr = curr_pt & physical_frame_mask;
    
	//mark pte as invalid
	curr_pt &= ~(1 << 31);

	//write pte back to physical memory
	memcpy(physical_memory+page_table_address,&curr_pt,sizeof(pte_t));

	//mark va as free in virtual bitmap
	unsigned long va_to_free = (unsigned long)va;
	va_to_free = va_to_free >> num_bits_po;
	free_address_in_bitmap(va_to_free,virtual_bitmap,num_virtual_pages);

	//mark pa as free in physical bitmap
	free_address_in_bitmap(paddr,physical_bitmap,num_physical_pages);

	//make corresponding tlb entry invalid if tlb hit
	unsigned long id,tag;
	tag = va_to_free & tlb_tag_mask;
	va_to_free = va_to_free >> num_bits_tlb_tag;
	id = va_to_free & tlb_id_mask;
	if(((tlb_store[id].valid_and_tag >> 31) & 1) == 1) {

		//tlb entry is valid
		unsigned long stored_tag = tlb_store[id].valid_and_tag & tlb_tag_mask;
		if(tag == stored_tag) { //tlb hit

			tlb_store[id].valid_and_tag &= ~(1 << 31);//making the entry invalid
		}
	}

	//check if all pte in current pde are valid or not
	//if all are invalid then set pde as invalid
	if(check_pde_valid(pgdir[page_directory_index]) == 0) {

		pgdir[page_directory_index] &= ~(1 << 31);//mark pde as invalid
		unsigned long physical_page_address = pgdir[page_directory_index] & physical_frame_mask;
		free_address_in_bitmap(physical_page_address,physical_bitmap,num_physical_pages);
	}

	//return success response
	return 1;  
}


/*
Function to check if all pages for va+size are valid
*/
int check_all_pages_valid(void *va, int size) {

	unsigned long vaddr = (unsigned long)va;
	int num_pages = size/PGSIZE + 1;
	pte_t *pte = NULL;

	int i;
	for(i=0;i<num_pages;i++) {

		pte = translate(pgdir,(void *)vaddr);
		if(pte == NULL || !is_pte_valid(*pte)) {

			//pte is not valid
			if(pte != NULL)
				free(pte);
			//returning since failure
			return 0;
		}
		free(pte);
		vaddr += (1 << num_bits_po);
	}

	//return all pages are valid
	return 1;
}


/* Responsible for releasing one or more memory pages using virtual address (va)
*/
void a_free(void *va, int size) {

	/* Part 1: Free the page table entries starting from this virtual address
	* (va). Also mark the pages free in the bitmap. Perform free only if the 
	* memory from "va" to va+size is valid.
	*
	* Part 2: Also, remove the translation from the TLB
	*/

	//lock mutex
	pthread_mutex_lock(&memory_lock);

	unsigned long vaddr = (unsigned long)va;
	int num_pages = size/PGSIZE + 1;

	if(check_all_pages_valid(va,size) == 0) {

		printf("not all virtual pages are valid\n");
		//quiting since not all pages are valid
		return;
	}

	int i;
	for(i=0;i<num_pages;i++) {

		page_unmap(pgdir,(void *)vaddr);
		vaddr += (1 << num_bits_po);
	}

	//unlock mutex
	pthread_mutex_unlock(&memory_lock);	
}


/* The function copies data pointed by "val" to physical
 * memory pages using virtual address (va)
*/
void put_value(void *va, void *val, int size) {

	/* HINT: Using the virtual address and translate(), find the physical page. Copy
	* the contents of "val" to a physical page. NOTE: The "size" value can be larger 
	* than one page. Therefore, you may have to find multiple pages using translate()
	* function.
	*/

	//lock mutex
	pthread_mutex_lock(&memory_lock);

	if(check_all_pages_valid(va,size) == 0) {

		printf("not all virtual pages are valid\n");
		//quiting since not all pages are valid
		return;
	}

	unsigned long vaddr = (unsigned long)va;
	int remaining_to_copy = size;

	while(remaining_to_copy > 0) {

		//try to find page table entry for given va
		pte_t *cur_pte = translate(pgdir,(void *)vaddr);

		if(cur_pte==NULL) {

			//pte is null
			printf("pte is NULL\n");
			return;
		}

		if(!is_pte_valid(*cur_pte)) {

			//pte is not valid
			printf("pte is not valid\n");
			free(cur_pte);
			return;
		}

		//pte is valid
		//fetch page offset from va
		unsigned long page_offset = vaddr & page_offset_mask;
		unsigned long physical_address = get_physical_address_from_pte_t(*cur_pte,page_offset);

		int source_offset = size - remaining_to_copy;
		//use physical_address to get pointer to physical memory
		if(remaining_to_copy >= PGSIZE) {

			memcpy(physical_memory+physical_address+source_offset,val+source_offset,PGSIZE);
			remaining_to_copy -= PGSIZE;
			//move vaddr to next page
			vaddr += (1 << num_bits_po);
		}
		else {

			memcpy(physical_memory+physical_address+source_offset,val+source_offset,remaining_to_copy);
			remaining_to_copy = 0;
		}
		free(cur_pte);
	}

	//unlock mutex
	pthread_mutex_unlock(&memory_lock);
}


/*Given a virtual address, this function copies the contents of the page to val*/
void get_value(void *va, void *val, int size) {

	/* HINT: put the values pointed to by "va" inside the physical memory at given
	* "val" address. Assume you can access "val" directly by derefencing them.
	*/

	//lock mutex
	pthread_mutex_lock(&memory_lock);

	if(check_all_pages_valid(va,size) == 0) {

		printf("not all virtual pages are valid\n");
		//quiting since not all pages are valid
		return;
	}

	unsigned long vaddr = (unsigned long)va;

	int remaining_to_copy = size;

	while(remaining_to_copy > 0) {

		//try to find page table entry for given va
		pte_t *cur_pte = translate(pgdir,(void *)vaddr);
		if(cur_pte==NULL) {

			//pte is null
			printf("pte is NULL\n");
			return;
		}

		if(!is_pte_valid(*cur_pte)) {

			//pte is not valid
			printf("pte is not valid\n");
			free(cur_pte);
			return;
		}

		//pte is valid
		//fetch page offset from va
		unsigned long page_offset = vaddr & page_offset_mask;
		unsigned long physical_address = get_physical_address_from_pte_t(*cur_pte,page_offset);

		int source_offset = size - remaining_to_copy;
		//use physical_address to get pointer to physical memory
		if(remaining_to_copy >= PGSIZE) {

			memcpy(val+source_offset,physical_memory+physical_address+source_offset,PGSIZE);
			remaining_to_copy -= PGSIZE;
			//move vaddr to next page
			vaddr += (1 << num_bits_po);
		}
		else {

			memcpy(val+source_offset,physical_memory+physical_address+source_offset,remaining_to_copy);
			remaining_to_copy = 0;
		}
		free(cur_pte);
	}

	//unlock mutex
	pthread_mutex_unlock(&memory_lock);
}



/*
This function receives two matrices mat1 and mat2 as an argument with size
argument representing the number of rows and columns. After performing matrix
multiplication, copy the result to answer.
*/
void mat_mult(void *mat1, void *mat2, int size, void *answer) {

	/* Hint: You will index as [i * size + j] where  "i, j" are the indices of the
	* matrix accessed. Similar to the code in test.c, you will use get_value() to
	* load each element and perform multiplication. Take a look at test.c! In addition to 
	* getting the values from two matrices, you will perform multiplication and 
	* store the result to the "answer array"
	*/
	//doing addition instead of mul
	int i,j,k;
	for(i=0;i<size;i++) {

		for(j=0;j<size;j++) {

			int r = 0;
			for(k=0;k<size;k++) {

				int v1,v2;

				//read input elements
				get_value((unsigned long)mat1+(i*size*sizeof(int))+k*sizeof(int),&v1,sizeof(int));
				get_value((unsigned long)mat2+(k*size*sizeof(int))+j*sizeof(int),&v2,sizeof(int));

				//calculate
				r += v1 * v2;
			}
			//store in the desired location
			put_value((unsigned long)answer+(i*size*sizeof(int))+j*sizeof(int),&r,sizeof(int));
		}
	}
}
