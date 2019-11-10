/*****************************************************************************
* Copyright (C) 2015 ARM Limited or its affiliates.	                     *
* This program is free software; you can redistribute it and/or modify it    *
* under the terms of the GNU General Public License as published by the Free *
* Software Foundation; either version 2 of the License, or (at your option)  *
* any later version.							     *
* This program is distributed in the hope that it will be useful, but 	     *
* WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY *
* or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License   *
* for more details.							     *
* You should have received a copy of the GNU General Public License along    *
* with this program; if not, write to the Free Software Foundation, 	     *
* Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.        *
******************************************************************************/
#ifndef __DX_CRYS_KERNEL_H__
#define __DX_CRYS_KERNEL_H__

// --------------------------------------
// BLOCK: MISC
// --------------------------------------
#define DX_AES_CLK_ENABLE_REG_OFFSET 	0x810UL
#define DX_AES_CLK_ENABLE_VALUE_BIT_SHIFT 	0x0UL
#define DX_AES_CLK_ENABLE_VALUE_BIT_SIZE 	0x1UL
#define DX_DES_CLK_ENABLE_REG_OFFSET 	0x814UL
#define DX_DES_CLK_ENABLE_VALUE_BIT_SHIFT 	0x0UL
#define DX_DES_CLK_ENABLE_VALUE_BIT_SIZE 	0x1UL
#define DX_HASH_CLK_ENABLE_REG_OFFSET 	0x818UL
#define DX_HASH_CLK_ENABLE_VALUE_BIT_SHIFT 	0x0UL
#define DX_HASH_CLK_ENABLE_VALUE_BIT_SIZE 	0x1UL
#define DX_PKA_CLK_ENABLE_REG_OFFSET 	0x81CUL
#define DX_PKA_CLK_ENABLE_VALUE_BIT_SHIFT 	0x0UL
#define DX_PKA_CLK_ENABLE_VALUE_BIT_SIZE 	0x1UL
#define DX_DMA_CLK_ENABLE_REG_OFFSET 	0x820UL
#define DX_DMA_CLK_ENABLE_VALUE_BIT_SHIFT 	0x0UL
#define DX_DMA_CLK_ENABLE_VALUE_BIT_SIZE 	0x1UL
#define DX_CLK_STATUS_REG_OFFSET 	0x824UL
#define DX_CLK_STATUS_AES_CLK_STATUS_BIT_SHIFT 	0x0UL
#define DX_CLK_STATUS_AES_CLK_STATUS_BIT_SIZE 	0x1UL
#define DX_CLK_STATUS_DES_CLK_STATUS_BIT_SHIFT 	0x1UL
#define DX_CLK_STATUS_DES_CLK_STATUS_BIT_SIZE 	0x1UL
#define DX_CLK_STATUS_HASH_CLK_STATUS_BIT_SHIFT 	0x2UL
#define DX_CLK_STATUS_HASH_CLK_STATUS_BIT_SIZE 	0x1UL
#define DX_CLK_STATUS_PKA_CLK_STATUS_BIT_SHIFT 	0x3UL
#define DX_CLK_STATUS_PKA_CLK_STATUS_BIT_SIZE 	0x1UL
#define DX_CLK_STATUS_RC4_CLK_STATUS_BIT_SHIFT 	0x4UL
#define DX_CLK_STATUS_RC4_CLK_STATUS_BIT_SIZE 	0x1UL
#define DX_CLK_STATUS_C2_CLK_STATUS_BIT_SHIFT 	0x7UL
#define DX_CLK_STATUS_C2_CLK_STATUS_BIT_SIZE 	0x1UL
#define DX_CLK_STATUS_DMA_CLK_STATUS_BIT_SHIFT 	0x8UL
#define DX_CLK_STATUS_DMA_CLK_STATUS_BIT_SIZE 	0x1UL
#define DX_RC4_CLK_ENABLE_REG_OFFSET 	0x854UL
#define DX_RC4_CLK_ENABLE_VALUE_BIT_SHIFT 	0x0UL
#define DX_RC4_CLK_ENABLE_VALUE_BIT_SIZE 	0x1UL
#define DX_MULTI2_CLK_ENABLE_REG_OFFSET 	0x858UL
#define DX_MULTI2_CLK_ENABLE_VALUE_BIT_SHIFT 	0x0UL
#define DX_MULTI2_CLK_ENABLE_VALUE_BIT_SIZE 	0x1UL
// --------------------------------------
// BLOCK: CC_CTL
// --------------------------------------
#define DX_CRYPTO_CTL_REG_OFFSET 	0x900UL
#define DX_CRYPTO_CTL_VALUE_BIT_SHIFT 	0x0UL
#define DX_CRYPTO_CTL_VALUE_BIT_SIZE 	0x5UL
#define DX_CRYPTO_BUSY_REG_OFFSET 	0x910UL
#define DX_CRYPTO_BUSY_VALUE_BIT_SHIFT 	0x0UL
#define DX_CRYPTO_BUSY_VALUE_BIT_SIZE 	0x1UL
#define DX_HASH_BUSY_REG_OFFSET 	0x91CUL
#define DX_HASH_BUSY_VALUE_BIT_SHIFT 	0x0UL
#define DX_HASH_BUSY_VALUE_BIT_SIZE 	0x1UL
#define DX_VERSION_REG_OFFSET 	0x928UL
#define DX_VERSION_VALUE_BIT_SHIFT 	0x0UL
#define DX_VERSION_VALUE_BIT_SIZE 	0x20UL
#define DX_CONTEXT_ID_REG_OFFSET 	0x930UL
#define DX_CONTEXT_ID_VALUE_BIT_SHIFT 	0x0UL
#define DX_CONTEXT_ID_VALUE_BIT_SIZE 	0x8UL
#define DX_HASH_COMPARE_ERR_ID_FIFO0_REG_OFFSET 	0x940UL
#define DX_HASH_COMPARE_ERR_ID_FIFO0_VALUE_BIT_SHIFT 	0x0UL
#define DX_HASH_COMPARE_ERR_ID_FIFO0_VALUE_BIT_SIZE 	0x1AUL
#define DX_HASH_COMPARE_ERR_ID_FIFO1_REG_OFFSET 	0x944UL
#define DX_HASH_COMPARE_ERR_ID_FIFO1_VALUE_BIT_SHIFT 	0x0UL
#define DX_HASH_COMPARE_ERR_ID_FIFO1_VALUE_BIT_SIZE 	0x1AUL
#define DX_HASH_COMPARE_ERR_ID_FIFO2_REG_OFFSET 	0x948UL
#define DX_HASH_COMPARE_ERR_ID_FIFO2_VALUE_BIT_SHIFT 	0x0UL
#define DX_HASH_COMPARE_ERR_ID_FIFO2_VALUE_BIT_SIZE 	0x1AUL
#define DX_HASH_COMPARE_ERR_ID_FIFO3_REG_OFFSET 	0x94CUL
#define DX_HASH_COMPARE_ERR_ID_FIFO3_VALUE_BIT_SHIFT 	0x0UL
#define DX_HASH_COMPARE_ERR_ID_FIFO3_VALUE_BIT_SIZE 	0x1AUL
// --------------------------------------
// BLOCK: DIN
// --------------------------------------
#define DX_DIN_BUFFER_REG_OFFSET 	0xC00UL
#define DX_DIN_BUFFER_VALUE_BIT_SHIFT 	0x0UL
#define DX_DIN_BUFFER_VALUE_BIT_SIZE 	0x20UL
#define DX_DIN_MEM_DMA_BUSY_REG_OFFSET 	0xC20UL
#define DX_DIN_MEM_DMA_BUSY_VALUE_BIT_SHIFT 	0x0UL
#define DX_DIN_MEM_DMA_BUSY_VALUE_BIT_SIZE 	0x1UL
#define DX_SRC_LLI_SRAM_ADDR_REG_OFFSET 	0xC24UL
#define DX_SRC_LLI_SRAM_ADDR_VALUE_BIT_SHIFT 	0x0UL
#define DX_SRC_LLI_SRAM_ADDR_VALUE_BIT_SIZE 	0xFUL
#define DX_SRC_LLI_WORD0_REG_OFFSET 	0xC28UL
#define DX_SRC_LLI_WORD0_VALUE_BIT_SHIFT 	0x0UL
#define DX_SRC_LLI_WORD0_VALUE_BIT_SIZE 	0x20UL
#define DX_SRC_LLI_WORD1_REG_OFFSET 	0xC2CUL
#define DX_SRC_LLI_WORD1_BYTES_NUM_BIT_SHIFT 	0x0UL
#define DX_SRC_LLI_WORD1_BYTES_NUM_BIT_SIZE 	0x1EUL
#define DX_SRC_LLI_WORD1_FIRST_BIT_SHIFT 	0x1EUL
#define DX_SRC_LLI_WORD1_FIRST_BIT_SIZE 	0x1UL
#define DX_SRC_LLI_WORD1_LAST_BIT_SHIFT 	0x1FUL
#define DX_SRC_LLI_WORD1_LAST_BIT_SIZE 	0x1UL
#define DX_SRAM_SRC_ADDR_REG_OFFSET 	0xC30UL
#define DX_SRAM_SRC_ADDR_VALUE_BIT_SHIFT 	0x0UL
#define DX_SRAM_SRC_ADDR_VALUE_BIT_SIZE 	0x20UL
#define DX_DIN_SRAM_BYTES_LEN_REG_OFFSET 	0xC34UL
#define DX_DIN_SRAM_BYTES_LEN_VALUE_BIT_SHIFT 	0x0UL
#define DX_DIN_SRAM_BYTES_LEN_VALUE_BIT_SIZE 	0x20UL
#define DX_DIN_SRAM_DMA_BUSY_REG_OFFSET 	0xC38UL
#define DX_DIN_SRAM_DMA_BUSY_VALUE_BIT_SHIFT 	0x0UL
#define DX_DIN_SRAM_DMA_BUSY_VALUE_BIT_SIZE 	0x1UL
#define DX_DIN_SRAM_ENDIANNESS_REG_OFFSET 	0xC3CUL
#define DX_DIN_SRAM_ENDIANNESS_VALUE_BIT_SHIFT 	0x0UL
#define DX_DIN_SRAM_ENDIANNESS_VALUE_BIT_SIZE 	0x1UL
#define DX_AXI_CPU_DIN_PARAMS_REG_OFFSET 	0xC40UL
#define DX_AXI_CPU_DIN_PARAMS_RDID_BIT_SHIFT 	0x0UL
#define DX_AXI_CPU_DIN_PARAMS_RDID_BIT_SIZE 	0x4UL
#define DX_AXI_CPU_DIN_PARAMS_PROT_BIT_SHIFT 	0x8UL
#define DX_AXI_CPU_DIN_PARAMS_PROT_BIT_SIZE 	0x2UL
#define DX_DIN_SW_RESET_REG_OFFSET 	0xC44UL
#define DX_DIN_SW_RESET_VALUE_BIT_SHIFT 	0x0UL
#define DX_DIN_SW_RESET_VALUE_BIT_SIZE 	0x1UL
#define DX_DIN_CPU_DATA_SIZE_REG_OFFSET 	0xC48UL
#define DX_DIN_CPU_DATA_SIZE_VALUE_BIT_SHIFT 	0x0UL
#define DX_DIN_CPU_DATA_SIZE_VALUE_BIT_SIZE 	0x10UL
#define DX_WRITE_ALIGN_LAST_REG_OFFSET 	0xC4CUL
#define DX_WRITE_ALIGN_LAST_VALUE_BIT_SHIFT 	0x0UL
#define DX_WRITE_ALIGN_LAST_VALUE_BIT_SIZE 	0x1UL
#define DX_FIFO_IN_EMPTY_REG_OFFSET 	0xC50UL
#define DX_FIFO_IN_EMPTY_VALUE_BIT_SHIFT 	0x0UL
#define DX_FIFO_IN_EMPTY_VALUE_BIT_SIZE 	0x1UL
#define DX_DISABLE_OUTSTD_REQ_REG_OFFSET 	0xC54UL
#define DX_DISABLE_OUTSTD_REQ_VALUE_BIT_SHIFT 	0x0UL
#define DX_DISABLE_OUTSTD_REQ_VALUE_BIT_SIZE 	0x1UL
#define DX_DIN_FIFO_RST_PNTR_REG_OFFSET 	0xC58UL
#define DX_DIN_FIFO_RST_PNTR_VALUE_BIT_SHIFT 	0x0UL
#define DX_DIN_FIFO_RST_PNTR_VALUE_BIT_SIZE 	0x1UL
// --------------------------------------
// BLOCK: DOUT
// --------------------------------------
#define DX_DOUT_BUFFER_REG_OFFSET 	0xD00UL
#define DX_DOUT_BUFFER_VALUE_BIT_SHIFT 	0x0UL
#define DX_DOUT_BUFFER_VALUE_BIT_SIZE 	0x20UL
#define DX_DOUT_MEM_DMA_BUSY_REG_OFFSET 	0xD20UL
#define DX_DOUT_MEM_DMA_BUSY_VALUE_BIT_SHIFT 	0x0UL
#define DX_DOUT_MEM_DMA_BUSY_VALUE_BIT_SIZE 	0x1UL
#define DX_DST_LLI_SRAM_ADDR_REG_OFFSET 	0xD24UL
#define DX_DST_LLI_SRAM_ADDR_VALUE_BIT_SHIFT 	0x0UL
#define DX_DST_LLI_SRAM_ADDR_VALUE_BIT_SIZE 	0xFUL
#define DX_DST_LLI_WORD0_REG_OFFSET 	0xD28UL
#define DX_DST_LLI_WORD0_VALUE_BIT_SHIFT 	0x0UL
#define DX_DST_LLI_WORD0_VALUE_BIT_SIZE 	0x20UL
#define DX_DST_LLI_WORD1_REG_OFFSET 	0xD2CUL
#define DX_DST_LLI_WORD1_BYTES_NUM_BIT_SHIFT 	0x0UL
#define DX_DST_LLI_WORD1_BYTES_NUM_BIT_SIZE 	0x1EUL
#define DX_DST_LLI_WORD1_FIRST_BIT_SHIFT 	0x1EUL
#define DX_DST_LLI_WORD1_FIRST_BIT_SIZE 	0x1UL
#define DX_DST_LLI_WORD1_LAST_BIT_SHIFT 	0x1FUL
#define DX_DST_LLI_WORD1_LAST_BIT_SIZE 	0x1UL
#define DX_SRAM_DEST_ADDR_REG_OFFSET 	0xD30UL
#define DX_SRAM_DEST_ADDR_VALUE_BIT_SHIFT 	0x0UL
#define DX_SRAM_DEST_ADDR_VALUE_BIT_SIZE 	0x20UL
#define DX_DOUT_SRAM_BYTES_LEN_REG_OFFSET 	0xD34UL
#define DX_DOUT_SRAM_BYTES_LEN_VALUE_BIT_SHIFT 	0x0UL
#define DX_DOUT_SRAM_BYTES_LEN_VALUE_BIT_SIZE 	0x20UL
#define DX_DOUT_SRAM_DMA_BUSY_REG_OFFSET 	0xD38UL
#define DX_DOUT_SRAM_DMA_BUSY_VALUE_BIT_SHIFT 	0x0UL
#define DX_DOUT_SRAM_DMA_BUSY_VALUE_BIT_SIZE 	0x1UL
#define DX_DOUT_SRAM_ENDIANNESS_REG_OFFSET 	0xD3CUL
#define DX_DOUT_SRAM_ENDIANNESS_VALUE_BIT_SHIFT 	0x0UL
#define DX_DOUT_SRAM_ENDIANNESS_VALUE_BIT_SIZE 	0x1UL
#define DX_READ_ALIGN_LAST_REG_OFFSET 	0xD44UL
#define DX_READ_ALIGN_LAST_VALUE_BIT_SHIFT 	0x0UL
#define DX_READ_ALIGN_LAST_VALUE_BIT_SIZE 	0x1UL
#define DX_FIFO_MODE_REG_OFFSET 	0xD48UL
#define DX_FIFO_MODE_VALUE_BIT_SHIFT 	0x0UL
#define DX_FIFO_MODE_VALUE_BIT_SIZE 	0x1UL
#define DX_DOUT_FIFO_EMPTY_REG_OFFSET 	0xD50UL
#define DX_DOUT_FIFO_EMPTY_VALUE_BIT_SHIFT 	0x0UL
#define DX_DOUT_FIFO_EMPTY_VALUE_BIT_SIZE 	0x1UL
#define DX_AXI_CPU_DOUT_PARAMS_REG_OFFSET 	0xD54UL
#define DX_AXI_CPU_DOUT_PARAMS_CACHE_TYPE_BIT_SHIFT 	0x0UL
#define DX_AXI_CPU_DOUT_PARAMS_CACHE_TYPE_BIT_SIZE 	0x4UL
#define DX_AXI_CPU_DOUT_PARAMS_WRID_BIT_SHIFT 	0xCUL
#define DX_AXI_CPU_DOUT_PARAMS_WRID_BIT_SIZE 	0x4UL
#define DX_AXI_CPU_DOUT_PARAMS_PROT_BIT_SHIFT 	0x10UL
#define DX_AXI_CPU_DOUT_PARAMS_PROT_BIT_SIZE 	0x2UL
#define DX_AXI_CPU_DOUT_PARAMS_FORCE_CPU_PARAMS_BIT_SHIFT 	0x12UL
#define DX_AXI_CPU_DOUT_PARAMS_FORCE_CPU_PARAMS_BIT_SIZE 	0x1UL
#define DX_DOUT_SW_RESET_REG_OFFSET 	0xD58UL
#define DX_DOUT_SW_RESET_VALUE_BIT_SHIFT 	0x0UL
#define DX_DOUT_SW_RESET_VALUE_BIT_SIZE 	0x1UL
// --------------------------------------
// BLOCK: DSCRPTR
// --------------------------------------
#define DX_DSCRPTR_COMPLETION_COUNTER0_REG_OFFSET 	0xE00UL
#define DX_DSCRPTR_COMPLETION_COUNTER0_COMPLETION_COUNTER_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_COMPLETION_COUNTER0_COMPLETION_COUNTER_BIT_SIZE 	0x6UL
#define DX_DSCRPTR_COMPLETION_COUNTER0_OVERFLOW_COUNTER_BIT_SHIFT 	0x6UL
#define DX_DSCRPTR_COMPLETION_COUNTER0_OVERFLOW_COUNTER_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_COMPLETION_COUNTER1_REG_OFFSET 	0xE04UL
#define DX_DSCRPTR_COMPLETION_COUNTER1_COMPLETION_COUNTER_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_COMPLETION_COUNTER1_COMPLETION_COUNTER_BIT_SIZE 	0x6UL
#define DX_DSCRPTR_COMPLETION_COUNTER1_OVERFLOW_COUNTER_BIT_SHIFT 	0x6UL
#define DX_DSCRPTR_COMPLETION_COUNTER1_OVERFLOW_COUNTER_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_COMPLETION_STATUS_REG_OFFSET 	0xE3CUL
#define DX_DSCRPTR_COMPLETION_STATUS_VALUE_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_COMPLETION_STATUS_VALUE_BIT_SIZE 	0x2UL
#define DX_DSCRPTR_SW_RESET_REG_OFFSET 	0xE40UL
#define DX_DSCRPTR_SW_RESET_VALUE_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_SW_RESET_VALUE_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_CNTX_SWITCH_COUNTER_VAL_REG_OFFSET 	0xE44UL
#define DX_DSCRPTR_CNTX_SWITCH_COUNTER_VAL_VALUE_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_CNTX_SWITCH_COUNTER_VAL_VALUE_BIT_SIZE 	0x20UL
#define DX_DSCRPTR_DISABLE_CNTX_SWITCH_REG_OFFSET 	0xE48UL
#define DX_DSCRPTR_DISABLE_CNTX_SWITCH_VALUE_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_DISABLE_CNTX_SWITCH_VALUE_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_DEBUG_MODE_REG_OFFSET 	0xE4CUL
#define DX_DSCRPTR_DEBUG_MODE_VALUE_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_DEBUG_MODE_VALUE_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_FILTER_DROPPED_CNT_REG_OFFSET 	0xE50UL
#define DX_DSCRPTR_FILTER_DROPPED_CNT_VALUE_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_FILTER_DROPPED_CNT_VALUE_BIT_SIZE 	0x20UL
#define DX_DSCRPTR_FILTER_DROPPED_MEM_CNT_REG_OFFSET 	0xE54UL
#define DX_DSCRPTR_FILTER_DROPPED_MEM_CNT_VALUE_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_FILTER_DROPPED_MEM_CNT_VALUE_BIT_SIZE 	0x20UL
#define DX_DSCRPTR_FILTER_DEBUG_REG_OFFSET 	0xE58UL
#define DX_DSCRPTR_FILTER_DEBUG_VALUE_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_FILTER_DEBUG_VALUE_BIT_SIZE 	0x8UL
#define DX_DSCRPTR_FILTER_DROPPED_ADDRESS_REG_OFFSET 	0xE5CUL
#define DX_DSCRPTR_FILTER_DROPPED_ADDRESS_VALUE_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_FILTER_DROPPED_ADDRESS_VALUE_BIT_SIZE 	0x20UL
#define DX_DSCRPTR_QUEUE_SRAM_SIZE_REG_OFFSET 	0xE60UL
#define DX_DSCRPTR_QUEUE_SRAM_SIZE_VALUE_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_QUEUE_SRAM_SIZE_VALUE_BIT_SIZE 	0xAUL
#define DX_DSCRPTR_SINGLE_ADDR_EN_REG_OFFSET 	0xE64UL
#define DX_DSCRPTR_SINGLE_ADDR_EN_VALUE_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_SINGLE_ADDR_EN_VALUE_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_MEASURE_CNTR_REG_OFFSET 	0xE68UL
#define DX_DSCRPTR_MEASURE_CNTR_VALUE_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_MEASURE_CNTR_VALUE_BIT_SIZE 	0x20UL
#define DX_DSCRPTR_FILTER_DROPPED_ADDRESS_HIGH_REG_OFFSET 	0xE6CUL
#define DX_DSCRPTR_FILTER_DROPPED_ADDRESS_HIGH_VALUE_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_FILTER_DROPPED_ADDRESS_HIGH_VALUE_BIT_SIZE 	0x10UL
#define DX_DSCRPTR_QUEUE0_WORD0_REG_OFFSET 	0xE80UL
#define DX_DSCRPTR_QUEUE0_WORD0_VALUE_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_QUEUE0_WORD0_VALUE_BIT_SIZE 	0x20UL
#define DX_DSCRPTR_QUEUE0_WORD1_REG_OFFSET 	0xE84UL
#define DX_DSCRPTR_QUEUE0_WORD1_DIN_DMA_MODE_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_QUEUE0_WORD1_DIN_DMA_MODE_BIT_SIZE 	0x2UL
#define DX_DSCRPTR_QUEUE0_WORD1_DIN_SIZE_BIT_SHIFT 	0x2UL
#define DX_DSCRPTR_QUEUE0_WORD1_DIN_SIZE_BIT_SIZE 	0x18UL
#define DX_DSCRPTR_QUEUE0_WORD1_NS_BIT_BIT_SHIFT 	0x1AUL
#define DX_DSCRPTR_QUEUE0_WORD1_NS_BIT_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE0_WORD1_DIN_CONST_VALUE_BIT_SHIFT 	0x1BUL
#define DX_DSCRPTR_QUEUE0_WORD1_DIN_CONST_VALUE_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE0_WORD1_NOT_LAST_BIT_SHIFT 	0x1CUL
#define DX_DSCRPTR_QUEUE0_WORD1_NOT_LAST_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE0_WORD1_LOCK_QUEUE_BIT_SHIFT 	0x1DUL
#define DX_DSCRPTR_QUEUE0_WORD1_LOCK_QUEUE_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE0_WORD1_DIN_VIRTUAL_HOST_BIT_SHIFT 	0x1EUL
#define DX_DSCRPTR_QUEUE0_WORD1_DIN_VIRTUAL_HOST_BIT_SIZE 	0x2UL
#define DX_DSCRPTR_QUEUE0_WORD2_REG_OFFSET 	0xE88UL
#define DX_DSCRPTR_QUEUE0_WORD2_VALUE_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_QUEUE0_WORD2_VALUE_BIT_SIZE 	0x20UL
#define DX_DSCRPTR_QUEUE0_WORD3_REG_OFFSET 	0xE8CUL
#define DX_DSCRPTR_QUEUE0_WORD3_DOUT_DMA_MODE_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_QUEUE0_WORD3_DOUT_DMA_MODE_BIT_SIZE 	0x2UL
#define DX_DSCRPTR_QUEUE0_WORD3_DOUT_SIZE_BIT_SHIFT 	0x2UL
#define DX_DSCRPTR_QUEUE0_WORD3_DOUT_SIZE_BIT_SIZE 	0x18UL
#define DX_DSCRPTR_QUEUE0_WORD3_NS_BIT_BIT_SHIFT 	0x1AUL
#define DX_DSCRPTR_QUEUE0_WORD3_NS_BIT_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE0_WORD3_DOUT_LAST_IND_BIT_SHIFT 	0x1BUL
#define DX_DSCRPTR_QUEUE0_WORD3_DOUT_LAST_IND_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE0_WORD3_HASH_XOR_BIT_BIT_SHIFT 	0x1DUL
#define DX_DSCRPTR_QUEUE0_WORD3_HASH_XOR_BIT_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE0_WORD3_DOUT_VIRTUAL_HOST_BIT_SHIFT 	0x1EUL
#define DX_DSCRPTR_QUEUE0_WORD3_DOUT_VIRTUAL_HOST_BIT_SIZE 	0x2UL
#define DX_DSCRPTR_QUEUE0_WORD4_REG_OFFSET 	0xE90UL
#define DX_DSCRPTR_QUEUE0_WORD4_DATA_FLOW_MODE_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_QUEUE0_WORD4_DATA_FLOW_MODE_BIT_SIZE 	0x6UL
#define DX_DSCRPTR_QUEUE0_WORD4_AES_SEL_N_HASH_BIT_SHIFT 	0x6UL
#define DX_DSCRPTR_QUEUE0_WORD4_AES_SEL_N_HASH_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE0_WORD4_AES_XOR_CRYPTO_KEY_BIT_SHIFT 	0x7UL
#define DX_DSCRPTR_QUEUE0_WORD4_AES_XOR_CRYPTO_KEY_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE0_WORD4_ACK_NEEDED_BIT_SHIFT 	0x8UL
#define DX_DSCRPTR_QUEUE0_WORD4_ACK_NEEDED_BIT_SIZE 	0x2UL
#define DX_DSCRPTR_QUEUE0_WORD4_CIPHER_MODE_BIT_SHIFT 	0xAUL
#define DX_DSCRPTR_QUEUE0_WORD4_CIPHER_MODE_BIT_SIZE 	0x4UL
#define DX_DSCRPTR_QUEUE0_WORD4_CMAC_SIZE0_BIT_SHIFT 	0xEUL
#define DX_DSCRPTR_QUEUE0_WORD4_CMAC_SIZE0_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE0_WORD4_CIPHER_DO_BIT_SHIFT 	0xFUL
#define DX_DSCRPTR_QUEUE0_WORD4_CIPHER_DO_BIT_SIZE 	0x2UL
#define DX_DSCRPTR_QUEUE0_WORD4_CIPHER_CONF0_BIT_SHIFT 	0x11UL
#define DX_DSCRPTR_QUEUE0_WORD4_CIPHER_CONF0_BIT_SIZE 	0x2UL
#define DX_DSCRPTR_QUEUE0_WORD4_CIPHER_CONF1_BIT_SHIFT 	0x13UL
#define DX_DSCRPTR_QUEUE0_WORD4_CIPHER_CONF1_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE0_WORD4_CIPHER_CONF2_BIT_SHIFT 	0x14UL
#define DX_DSCRPTR_QUEUE0_WORD4_CIPHER_CONF2_BIT_SIZE 	0x2UL
#define DX_DSCRPTR_QUEUE0_WORD4_KEY_SIZE_BIT_SHIFT 	0x16UL
#define DX_DSCRPTR_QUEUE0_WORD4_KEY_SIZE_BIT_SIZE 	0x2UL
#define DX_DSCRPTR_QUEUE0_WORD4_SETUP_OPERATION_BIT_SHIFT 	0x18UL
#define DX_DSCRPTR_QUEUE0_WORD4_SETUP_OPERATION_BIT_SIZE 	0x4UL
#define DX_DSCRPTR_QUEUE0_WORD4_DIN_SRAM_ENDIANNESS_BIT_SHIFT 	0x1CUL
#define DX_DSCRPTR_QUEUE0_WORD4_DIN_SRAM_ENDIANNESS_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE0_WORD4_DOUT_SRAM_ENDIANNESS_BIT_SHIFT 	0x1DUL
#define DX_DSCRPTR_QUEUE0_WORD4_DOUT_SRAM_ENDIANNESS_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE0_WORD4_WORD_SWAP_BIT_SHIFT 	0x1EUL
#define DX_DSCRPTR_QUEUE0_WORD4_WORD_SWAP_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE0_WORD4_BYTES_SWAP_BIT_SHIFT 	0x1FUL
#define DX_DSCRPTR_QUEUE0_WORD4_BYTES_SWAP_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE0_WORD5_REG_OFFSET 	0xE94UL
#define DX_DSCRPTR_QUEUE0_WORD5_DIN_ADDR_HIGH_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_QUEUE0_WORD5_DIN_ADDR_HIGH_BIT_SIZE 	0x10UL
#define DX_DSCRPTR_QUEUE0_WORD5_DOUT_ADDR_HIGH_BIT_SHIFT 	0x10UL
#define DX_DSCRPTR_QUEUE0_WORD5_DOUT_ADDR_HIGH_BIT_SIZE 	0x10UL
#define DX_DSCRPTR_QUEUE0_WATERMARK_REG_OFFSET 	0xE98UL
#define DX_DSCRPTR_QUEUE0_WATERMARK_VALUE_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_QUEUE0_WATERMARK_VALUE_BIT_SIZE 	0xAUL
#define DX_DSCRPTR_QUEUE0_CONTENT_REG_OFFSET 	0xE9CUL
#define DX_DSCRPTR_QUEUE0_CONTENT_VALUE_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_QUEUE0_CONTENT_VALUE_BIT_SIZE 	0xAUL
#define DX_DSCRPTR_QUEUE1_WORD0_REG_OFFSET 	0xEA0UL
#define DX_DSCRPTR_QUEUE1_WORD0_VALUE_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_QUEUE1_WORD0_VALUE_BIT_SIZE 	0x20UL
#define DX_DSCRPTR_QUEUE1_WORD1_REG_OFFSET 	0xEA4UL
#define DX_DSCRPTR_QUEUE1_WORD1_DIN_DMA_MODE_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_QUEUE1_WORD1_DIN_DMA_MODE_BIT_SIZE 	0x2UL
#define DX_DSCRPTR_QUEUE1_WORD1_DIN_SIZE_BIT_SHIFT 	0x2UL
#define DX_DSCRPTR_QUEUE1_WORD1_DIN_SIZE_BIT_SIZE 	0x18UL
#define DX_DSCRPTR_QUEUE1_WORD1_NS_BIT_BIT_SHIFT 	0x1AUL
#define DX_DSCRPTR_QUEUE1_WORD1_NS_BIT_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE1_WORD1_DIN_CONST_VALUE_BIT_SHIFT 	0x1BUL
#define DX_DSCRPTR_QUEUE1_WORD1_DIN_CONST_VALUE_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE1_WORD1_NOT_LAST_BIT_SHIFT 	0x1CUL
#define DX_DSCRPTR_QUEUE1_WORD1_NOT_LAST_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE1_WORD1_LOCK_QUEUE_BIT_SHIFT 	0x1DUL
#define DX_DSCRPTR_QUEUE1_WORD1_LOCK_QUEUE_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE1_WORD1_DIN_VIRTUAL_HOST_BIT_SHIFT 	0x1EUL
#define DX_DSCRPTR_QUEUE1_WORD1_DIN_VIRTUAL_HOST_BIT_SIZE 	0x2UL
#define DX_DSCRPTR_QUEUE1_WORD2_REG_OFFSET 	0xEA8UL
#define DX_DSCRPTR_QUEUE1_WORD2_VALUE_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_QUEUE1_WORD2_VALUE_BIT_SIZE 	0x20UL
#define DX_DSCRPTR_QUEUE1_WORD3_REG_OFFSET 	0xEACUL
#define DX_DSCRPTR_QUEUE1_WORD3_DOUT_DMA_MODE_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_QUEUE1_WORD3_DOUT_DMA_MODE_BIT_SIZE 	0x2UL
#define DX_DSCRPTR_QUEUE1_WORD3_DOUT_SIZE_BIT_SHIFT 	0x2UL
#define DX_DSCRPTR_QUEUE1_WORD3_DOUT_SIZE_BIT_SIZE 	0x18UL
#define DX_DSCRPTR_QUEUE1_WORD3_NS_BIT_BIT_SHIFT 	0x1AUL
#define DX_DSCRPTR_QUEUE1_WORD3_NS_BIT_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE1_WORD3_DOUT_LAST_IND_BIT_SHIFT 	0x1BUL
#define DX_DSCRPTR_QUEUE1_WORD3_DOUT_LAST_IND_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE1_WORD3_HASH_XOR_BIT_BIT_SHIFT 	0x1DUL
#define DX_DSCRPTR_QUEUE1_WORD3_HASH_XOR_BIT_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE1_WORD3_DOUT_VIRTUAL_HOST_BIT_SHIFT 	0x1EUL
#define DX_DSCRPTR_QUEUE1_WORD3_DOUT_VIRTUAL_HOST_BIT_SIZE 	0x2UL
#define DX_DSCRPTR_QUEUE1_WORD4_REG_OFFSET 	0xEB0UL
#define DX_DSCRPTR_QUEUE1_WORD4_DATA_FLOW_MODE_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_QUEUE1_WORD4_DATA_FLOW_MODE_BIT_SIZE 	0x6UL
#define DX_DSCRPTR_QUEUE1_WORD4_AES_SEL_N_HASH_BIT_SHIFT 	0x6UL
#define DX_DSCRPTR_QUEUE1_WORD4_AES_SEL_N_HASH_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE1_WORD4_AES_XOR_CRYPTO_KEY_BIT_SHIFT 	0x7UL
#define DX_DSCRPTR_QUEUE1_WORD4_AES_XOR_CRYPTO_KEY_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE1_WORD4_ACK_NEEDED_BIT_SHIFT 	0x8UL
#define DX_DSCRPTR_QUEUE1_WORD4_ACK_NEEDED_BIT_SIZE 	0x2UL
#define DX_DSCRPTR_QUEUE1_WORD4_CIPHER_MODE_BIT_SHIFT 	0xAUL
#define DX_DSCRPTR_QUEUE1_WORD4_CIPHER_MODE_BIT_SIZE 	0x4UL
#define DX_DSCRPTR_QUEUE1_WORD4_CMAC_SIZE0_BIT_SHIFT 	0xEUL
#define DX_DSCRPTR_QUEUE1_WORD4_CMAC_SIZE0_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE1_WORD4_CIPHER_DO_BIT_SHIFT 	0xFUL
#define DX_DSCRPTR_QUEUE1_WORD4_CIPHER_DO_BIT_SIZE 	0x2UL
#define DX_DSCRPTR_QUEUE1_WORD4_CIPHER_CONF0_BIT_SHIFT 	0x11UL
#define DX_DSCRPTR_QUEUE1_WORD4_CIPHER_CONF0_BIT_SIZE 	0x2UL
#define DX_DSCRPTR_QUEUE1_WORD4_CIPHER_CONF1_BIT_SHIFT 	0x13UL
#define DX_DSCRPTR_QUEUE1_WORD4_CIPHER_CONF1_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE1_WORD4_CIPHER_CONF2_BIT_SHIFT 	0x14UL
#define DX_DSCRPTR_QUEUE1_WORD4_CIPHER_CONF2_BIT_SIZE 	0x2UL
#define DX_DSCRPTR_QUEUE1_WORD4_KEY_SIZE_BIT_SHIFT 	0x16UL
#define DX_DSCRPTR_QUEUE1_WORD4_KEY_SIZE_BIT_SIZE 	0x2UL
#define DX_DSCRPTR_QUEUE1_WORD4_SETUP_OPERATION_BIT_SHIFT 	0x18UL
#define DX_DSCRPTR_QUEUE1_WORD4_SETUP_OPERATION_BIT_SIZE 	0x4UL
#define DX_DSCRPTR_QUEUE1_WORD4_DIN_SRAM_ENDIANNESS_BIT_SHIFT 	0x1CUL
#define DX_DSCRPTR_QUEUE1_WORD4_DIN_SRAM_ENDIANNESS_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE1_WORD4_DOUT_SRAM_ENDIANNESS_BIT_SHIFT 	0x1DUL
#define DX_DSCRPTR_QUEUE1_WORD4_DOUT_SRAM_ENDIANNESS_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE1_WORD4_WORD_SWAP_BIT_SHIFT 	0x1EUL
#define DX_DSCRPTR_QUEUE1_WORD4_WORD_SWAP_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE1_WORD4_BYTES_SWAP_BIT_SHIFT 	0x1FUL
#define DX_DSCRPTR_QUEUE1_WORD4_BYTES_SWAP_BIT_SIZE 	0x1UL
#define DX_DSCRPTR_QUEUE1_WORD5_REG_OFFSET 	0xEB4UL
#define DX_DSCRPTR_QUEUE1_WORD5_DIN_ADDR_HIGH_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_QUEUE1_WORD5_DIN_ADDR_HIGH_BIT_SIZE 	0x10UL
#define DX_DSCRPTR_QUEUE1_WORD5_DOUT_ADDR_HIGH_BIT_SHIFT 	0x10UL
#define DX_DSCRPTR_QUEUE1_WORD5_DOUT_ADDR_HIGH_BIT_SIZE 	0x10UL
#define DX_DSCRPTR_QUEUE1_WATERMARK_REG_OFFSET 	0xEB8UL
#define DX_DSCRPTR_QUEUE1_WATERMARK_VALUE_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_QUEUE1_WATERMARK_VALUE_BIT_SIZE 	0xAUL
#define DX_DSCRPTR_QUEUE1_CONTENT_REG_OFFSET 	0xEBCUL
#define DX_DSCRPTR_QUEUE1_CONTENT_VALUE_BIT_SHIFT 	0x0UL
#define DX_DSCRPTR_QUEUE1_CONTENT_VALUE_BIT_SIZE 	0xAUL
// --------------------------------------
// BLOCK: AXI
// --------------------------------------
#define DX_AXIM_MON_INFLIGHT0_REG_OFFSET 	0xB00UL
#define DX_AXIM_MON_INFLIGHT0_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_INFLIGHT0_VALUE_BIT_SIZE 	0x8UL
#define DX_AXIM_MON_INFLIGHT1_REG_OFFSET 	0xB04UL
#define DX_AXIM_MON_INFLIGHT1_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_INFLIGHT1_VALUE_BIT_SIZE 	0x8UL
#define DX_AXIM_MON_INFLIGHT2_REG_OFFSET 	0xB08UL
#define DX_AXIM_MON_INFLIGHT2_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_INFLIGHT2_VALUE_BIT_SIZE 	0x8UL
#define DX_AXIM_MON_INFLIGHT3_REG_OFFSET 	0xB0CUL
#define DX_AXIM_MON_INFLIGHT3_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_INFLIGHT3_VALUE_BIT_SIZE 	0x8UL
#define DX_AXIM_MON_INFLIGHT4_REG_OFFSET 	0xB10UL
#define DX_AXIM_MON_INFLIGHT4_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_INFLIGHT4_VALUE_BIT_SIZE 	0x8UL
#define DX_AXIM_MON_INFLIGHT5_REG_OFFSET 	0xB14UL
#define DX_AXIM_MON_INFLIGHT5_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_INFLIGHT5_VALUE_BIT_SIZE 	0x8UL
#define DX_AXIM_MON_INFLIGHT8_REG_OFFSET 	0xB20UL
#define DX_AXIM_MON_INFLIGHT8_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_INFLIGHT8_VALUE_BIT_SIZE 	0x8UL
#define DX_AXIM_MON_INFLIGHT9_REG_OFFSET 	0xB24UL
#define DX_AXIM_MON_INFLIGHT9_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_INFLIGHT9_VALUE_BIT_SIZE 	0x8UL
#define DX_AXIM_MON_INFLIGHT10_REG_OFFSET 	0xB28UL
#define DX_AXIM_MON_INFLIGHT10_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_INFLIGHT10_VALUE_BIT_SIZE 	0x8UL
#define DX_AXIM_MON_INFLIGHT11_REG_OFFSET 	0xB2CUL
#define DX_AXIM_MON_INFLIGHT11_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_INFLIGHT11_VALUE_BIT_SIZE 	0x8UL
#define DX_AXIM_MON_INFLIGHTLAST0_REG_OFFSET 	0xB40UL
#define DX_AXIM_MON_INFLIGHTLAST0_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_INFLIGHTLAST0_VALUE_BIT_SIZE 	0x8UL
#define DX_AXIM_MON_INFLIGHTLAST1_REG_OFFSET 	0xB44UL
#define DX_AXIM_MON_INFLIGHTLAST1_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_INFLIGHTLAST1_VALUE_BIT_SIZE 	0x8UL
#define DX_AXIM_MON_INFLIGHTLAST2_REG_OFFSET 	0xB48UL
#define DX_AXIM_MON_INFLIGHTLAST2_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_INFLIGHTLAST2_VALUE_BIT_SIZE 	0x8UL
#define DX_AXIM_MON_INFLIGHTLAST3_REG_OFFSET 	0xB4CUL
#define DX_AXIM_MON_INFLIGHTLAST3_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_INFLIGHTLAST3_VALUE_BIT_SIZE 	0x8UL
#define DX_AXIM_MON_INFLIGHTLAST4_REG_OFFSET 	0xB50UL
#define DX_AXIM_MON_INFLIGHTLAST4_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_INFLIGHTLAST4_VALUE_BIT_SIZE 	0x8UL
#define DX_AXIM_MON_INFLIGHTLAST5_REG_OFFSET 	0xB54UL
#define DX_AXIM_MON_INFLIGHTLAST5_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_INFLIGHTLAST5_VALUE_BIT_SIZE 	0x8UL
#define DX_AXIM_MON_INFLIGHTLAST8_REG_OFFSET 	0xB60UL
#define DX_AXIM_MON_INFLIGHTLAST8_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_INFLIGHTLAST8_VALUE_BIT_SIZE 	0x8UL
#define DX_AXIM_MON_INFLIGHTLAST9_REG_OFFSET 	0xB64UL
#define DX_AXIM_MON_INFLIGHTLAST9_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_INFLIGHTLAST9_VALUE_BIT_SIZE 	0x8UL
#define DX_AXIM_MON_INFLIGHTLAST10_REG_OFFSET 	0xB68UL
#define DX_AXIM_MON_INFLIGHTLAST10_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_INFLIGHTLAST10_VALUE_BIT_SIZE 	0x8UL
#define DX_AXIM_MON_INFLIGHTLAST11_REG_OFFSET 	0xB6CUL
#define DX_AXIM_MON_INFLIGHTLAST11_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_INFLIGHTLAST11_VALUE_BIT_SIZE 	0x8UL
#define DX_AXIM_PIDTABLE0_REG_OFFSET 	0xB70UL
#define DX_AXIM_PIDTABLE0_PID_BROKEN1_BIT_SHIFT 	0x0UL
#define DX_AXIM_PIDTABLE0_PID_BROKEN1_BIT_SIZE 	0x1UL
#define DX_AXIM_PIDTABLE0_PID_BROKEN2_BIT_SHIFT 	0x1UL
#define DX_AXIM_PIDTABLE0_PID_BROKEN2_BIT_SIZE 	0x1UL
#define DX_AXIM_PIDTABLE0_PID_OSCNTR_BIT_SHIFT 	0x2UL
#define DX_AXIM_PIDTABLE0_PID_OSCNTR_BIT_SIZE 	0x8UL
#define DX_AXIM_PIDTABLE0_PID_ID_BIT_SHIFT 	0xAUL
#define DX_AXIM_PIDTABLE0_PID_ID_BIT_SIZE 	0x5UL
#define DX_AXIM_PIDTABLE1_REG_OFFSET 	0xB74UL
#define DX_AXIM_PIDTABLE1_PID_BROKEN1_BIT_SHIFT 	0x0UL
#define DX_AXIM_PIDTABLE1_PID_BROKEN1_BIT_SIZE 	0x1UL
#define DX_AXIM_PIDTABLE1_PID_BROKEN2_BIT_SHIFT 	0x1UL
#define DX_AXIM_PIDTABLE1_PID_BROKEN2_BIT_SIZE 	0x1UL
#define DX_AXIM_PIDTABLE1_PID_OSCNTR_BIT_SHIFT 	0x2UL
#define DX_AXIM_PIDTABLE1_PID_OSCNTR_BIT_SIZE 	0x8UL
#define DX_AXIM_PIDTABLE1_PID_ID_BIT_SHIFT 	0xAUL
#define DX_AXIM_PIDTABLE1_PID_ID_BIT_SIZE 	0x5UL
#define DX_AXIM_PIDTABLE2_REG_OFFSET 	0xB78UL
#define DX_AXIM_PIDTABLE2_PID_BROKEN1_BIT_SHIFT 	0x0UL
#define DX_AXIM_PIDTABLE2_PID_BROKEN1_BIT_SIZE 	0x1UL
#define DX_AXIM_PIDTABLE2_PID_BROKEN2_BIT_SHIFT 	0x1UL
#define DX_AXIM_PIDTABLE2_PID_BROKEN2_BIT_SIZE 	0x1UL
#define DX_AXIM_PIDTABLE2_PID_OSCNTR_BIT_SHIFT 	0x2UL
#define DX_AXIM_PIDTABLE2_PID_OSCNTR_BIT_SIZE 	0x8UL
#define DX_AXIM_PIDTABLE2_PID_ID_BIT_SHIFT 	0xAUL
#define DX_AXIM_PIDTABLE2_PID_ID_BIT_SIZE 	0x5UL
#define DX_AXIM_PIDTABLE3_REG_OFFSET 	0xB7CUL
#define DX_AXIM_PIDTABLE3_PID_BROKEN1_BIT_SHIFT 	0x0UL
#define DX_AXIM_PIDTABLE3_PID_BROKEN1_BIT_SIZE 	0x1UL
#define DX_AXIM_PIDTABLE3_PID_BROKEN2_BIT_SHIFT 	0x1UL
#define DX_AXIM_PIDTABLE3_PID_BROKEN2_BIT_SIZE 	0x1UL
#define DX_AXIM_PIDTABLE3_PID_OSCNTR_BIT_SHIFT 	0x2UL
#define DX_AXIM_PIDTABLE3_PID_OSCNTR_BIT_SIZE 	0x8UL
#define DX_AXIM_PIDTABLE3_PID_ID_BIT_SHIFT 	0xAUL
#define DX_AXIM_PIDTABLE3_PID_ID_BIT_SIZE 	0x5UL
#define DX_AXIM_MON_COMP0_REG_OFFSET 	0xB80UL
#define DX_AXIM_MON_COMP0_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_COMP0_VALUE_BIT_SIZE 	0x10UL
#define DX_AXIM_MON_COMP1_REG_OFFSET 	0xB84UL
#define DX_AXIM_MON_COMP1_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_COMP1_VALUE_BIT_SIZE 	0x10UL
#define DX_AXIM_MON_COMP2_REG_OFFSET 	0xB88UL
#define DX_AXIM_MON_COMP2_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_COMP2_VALUE_BIT_SIZE 	0x10UL
#define DX_AXIM_MON_COMP3_REG_OFFSET 	0xB8CUL
#define DX_AXIM_MON_COMP3_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_COMP3_VALUE_BIT_SIZE 	0x10UL
#define DX_AXIM_MON_COMP4_REG_OFFSET 	0xB90UL
#define DX_AXIM_MON_COMP4_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_COMP4_VALUE_BIT_SIZE 	0x10UL
#define DX_AXIM_MON_COMP5_REG_OFFSET 	0xB94UL
#define DX_AXIM_MON_COMP5_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_COMP5_VALUE_BIT_SIZE 	0x10UL
#define DX_AXIM_MON_COMP8_REG_OFFSET 	0xBA0UL
#define DX_AXIM_MON_COMP8_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_COMP8_VALUE_BIT_SIZE 	0x10UL
#define DX_AXIM_MON_COMP9_REG_OFFSET 	0xBA4UL
#define DX_AXIM_MON_COMP9_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_COMP9_VALUE_BIT_SIZE 	0x10UL
#define DX_AXIM_MON_COMP10_REG_OFFSET 	0xBA8UL
#define DX_AXIM_MON_COMP10_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_COMP10_VALUE_BIT_SIZE 	0x10UL
#define DX_AXIM_MON_COMP11_REG_OFFSET 	0xBACUL
#define DX_AXIM_MON_COMP11_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_COMP11_VALUE_BIT_SIZE 	0x10UL
#define DX_AXIM_MON_RMAX_REG_OFFSET 	0xBB4UL
#define DX_AXIM_MON_RMAX_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_RMAX_VALUE_BIT_SIZE 	0x20UL
#define DX_AXIM_MON_RMIN_REG_OFFSET 	0xBB8UL
#define DX_AXIM_MON_RMIN_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_RMIN_VALUE_BIT_SIZE 	0x20UL
#define DX_AXIM_MON_WMAX_REG_OFFSET 	0xBBCUL
#define DX_AXIM_MON_WMAX_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_WMAX_VALUE_BIT_SIZE 	0x20UL
#define DX_AXIM_MON_WMIN_REG_OFFSET 	0xBC0UL
#define DX_AXIM_MON_WMIN_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_WMIN_VALUE_BIT_SIZE 	0x20UL
#define DX_AXIM_MON_ERR_REG_OFFSET 	0xBC4UL
#define DX_AXIM_MON_ERR_BRESP_BIT_SHIFT 	0x0UL
#define DX_AXIM_MON_ERR_BRESP_BIT_SIZE 	0x2UL
#define DX_AXIM_MON_ERR_BID_BIT_SHIFT 	0x2UL
#define DX_AXIM_MON_ERR_BID_BIT_SIZE 	0x4UL
#define DX_AXIM_MON_ERR_RRESP_BIT_SHIFT 	0x10UL
#define DX_AXIM_MON_ERR_RRESP_BIT_SIZE 	0x2UL
#define DX_AXIM_MON_ERR_RID_BIT_SHIFT 	0x12UL
#define DX_AXIM_MON_ERR_RID_BIT_SIZE 	0x4UL
#define DX_AXIM_RDSTAT_REG_OFFSET 	0xBC8UL
#define DX_AXIM_RDSTAT_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_RDSTAT_VALUE_BIT_SIZE 	0x4UL
#define DX_AXIM_RLATENCY_REG_OFFSET 	0xBD0UL
#define DX_AXIM_RLATENCY_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_RLATENCY_VALUE_BIT_SIZE 	0x20UL
#define DX_AXIM_RBURST_REG_OFFSET 	0xBD4UL
#define DX_AXIM_RBURST_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_RBURST_VALUE_BIT_SIZE 	0x20UL
#define DX_AXIM_WLATENCY_REG_OFFSET 	0xBD8UL
#define DX_AXIM_WLATENCY_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_WLATENCY_VALUE_BIT_SIZE 	0x20UL
#define DX_AXIM_WBURST_REG_OFFSET 	0xBDCUL
#define DX_AXIM_WBURST_VALUE_BIT_SHIFT 	0x0UL
#define DX_AXIM_WBURST_VALUE_BIT_SIZE 	0x20UL
#define DX_AXIM_CACHETYPE_CFG_REG_OFFSET 	0xBE0UL
#define DX_AXIM_CACHETYPE_CFG_ICACHE_ARCACHE_BIT_SHIFT 	0x0UL
#define DX_AXIM_CACHETYPE_CFG_ICACHE_ARCACHE_BIT_SIZE 	0x4UL
#define DX_AXIM_CACHETYPE_CFG_DCACHE_ARCACHE_BIT_SHIFT 	0x4UL
#define DX_AXIM_CACHETYPE_CFG_DCACHE_ARCACHE_BIT_SIZE 	0x4UL
#define DX_AXIM_CACHETYPE_CFG_DD_ARCACHE_BIT_SHIFT 	0x8UL
#define DX_AXIM_CACHETYPE_CFG_DD_ARCACHE_BIT_SIZE 	0x4UL
#define DX_AXIM_CACHETYPE_CFG_NOT_USED0_BIT_SHIFT 	0xCUL
#define DX_AXIM_CACHETYPE_CFG_NOT_USED0_BIT_SIZE 	0x4UL
#define DX_AXIM_CACHETYPE_CFG_ICACHE_AWCACHE_BIT_SHIFT 	0x10UL
#define DX_AXIM_CACHETYPE_CFG_ICACHE_AWCACHE_BIT_SIZE 	0x4UL
#define DX_AXIM_CACHETYPE_CFG_DCACHE_AWCACHE_BIT_SHIFT 	0x14UL
#define DX_AXIM_CACHETYPE_CFG_DCACHE_AWCACHE_BIT_SIZE 	0x4UL
#define DX_AXIM_CACHETYPE_CFG_DD_AWCACHE_BIT_SHIFT 	0x18UL
#define DX_AXIM_CACHETYPE_CFG_DD_AWCACHE_BIT_SIZE 	0x4UL
#define DX_AXIM_CACHETYPE_CFG_NOT_USED1_BIT_SHIFT 	0x1CUL
#define DX_AXIM_CACHETYPE_CFG_NOT_USED1_BIT_SIZE 	0x4UL
#define DX_AXIM_PROT_CFG_REG_OFFSET 	0xBE4UL
#define DX_AXIM_PROT_CFG_ICACHE_ARPROT_BIT_SHIFT 	0x0UL
#define DX_AXIM_PROT_CFG_ICACHE_ARPROT_BIT_SIZE 	0x2UL
#define DX_AXIM_PROT_CFG_DCACHE_ARPROT_BIT_SHIFT 	0x2UL
#define DX_AXIM_PROT_CFG_DCACHE_ARPROT_BIT_SIZE 	0x2UL
#define DX_AXIM_PROT_CFG_DD_ARPROT_BIT_SHIFT 	0x4UL
#define DX_AXIM_PROT_CFG_DD_ARPROT_BIT_SIZE 	0x1UL
#define DX_AXIM_PROT_CFG_NOT_USED0_BIT_SHIFT 	0x5UL
#define DX_AXIM_PROT_CFG_NOT_USED0_BIT_SIZE 	0x3UL
#define DX_AXIM_PROT_CFG_ICACHE_AWPROT_BIT_SHIFT 	0x8UL
#define DX_AXIM_PROT_CFG_ICACHE_AWPROT_BIT_SIZE 	0x2UL
#define DX_AXIM_PROT_CFG_DCACHE_AWPROT_BIT_SHIFT 	0xAUL
#define DX_AXIM_PROT_CFG_DCACHE_AWPROT_BIT_SIZE 	0x2UL
#define DX_AXIM_PROT_CFG_DD_AWPROT_BIT_SHIFT 	0xCUL
#define DX_AXIM_PROT_CFG_DD_AWPROT_BIT_SIZE 	0x1UL
#define DX_AXIM_PROT_CFG_NOT_USED1_BIT_SHIFT 	0xDUL
#define DX_AXIM_PROT_CFG_NOT_USED1_BIT_SIZE 	0x3UL
#define DX_AXIM_CFG1_REG_OFFSET 	0xBE8UL
#define DX_AXIM_CFG1_RD_AFTER_WR_STALL_BIT_SHIFT 	0x0UL
#define DX_AXIM_CFG1_RD_AFTER_WR_STALL_BIT_SIZE 	0x4UL
#define DX_AXIM_CFG1_BRESPMASK_BIT_SHIFT 	0x4UL
#define DX_AXIM_CFG1_BRESPMASK_BIT_SIZE 	0x1UL
#define DX_AXIM_CFG1_RRESPMASK_BIT_SHIFT 	0x5UL
#define DX_AXIM_CFG1_RRESPMASK_BIT_SIZE 	0x1UL
#define DX_AXIM_CFG1_INFLTMASK_BIT_SHIFT 	0x6UL
#define DX_AXIM_CFG1_INFLTMASK_BIT_SIZE 	0x1UL
#define DX_AXIM_CFG1_COMPMASK_BIT_SHIFT 	0x7UL
#define DX_AXIM_CFG1_COMPMASK_BIT_SIZE 	0x1UL
#define DX_AXIM_CFG1_ACCUM_LIMIT_BIT_SHIFT 	0x10UL
#define DX_AXIM_CFG1_ACCUM_LIMIT_BIT_SIZE 	0x5UL
#define DX_AXIM_ACE_CONST_REG_OFFSET 	0xBECUL
#define DX_AXIM_ACE_CONST_ARDOMAIN_BIT_SHIFT 	0x0UL
#define DX_AXIM_ACE_CONST_ARDOMAIN_BIT_SIZE 	0x2UL
#define DX_AXIM_ACE_CONST_AWDOMAIN_BIT_SHIFT 	0x2UL
#define DX_AXIM_ACE_CONST_AWDOMAIN_BIT_SIZE 	0x2UL
#define DX_AXIM_ACE_CONST_ARBAR_BIT_SHIFT 	0x4UL
#define DX_AXIM_ACE_CONST_ARBAR_BIT_SIZE 	0x2UL
#define DX_AXIM_ACE_CONST_AWBAR_BIT_SHIFT 	0x6UL
#define DX_AXIM_ACE_CONST_AWBAR_BIT_SIZE 	0x2UL
#define DX_AXIM_ACE_CONST_ARSNOOP_BIT_SHIFT 	0x8UL
#define DX_AXIM_ACE_CONST_ARSNOOP_BIT_SIZE 	0x4UL
#define DX_AXIM_ACE_CONST_AWSNOOP_NOT_ALIGNED_BIT_SHIFT 	0xCUL
#define DX_AXIM_ACE_CONST_AWSNOOP_NOT_ALIGNED_BIT_SIZE 	0x3UL
#define DX_AXIM_ACE_CONST_AWSNOOP_ALIGNED_BIT_SHIFT 	0xFUL
#define DX_AXIM_ACE_CONST_AWSNOOP_ALIGNED_BIT_SIZE 	0x3UL
#define DX_AXIM_ACE_CONST_AWADDR_NOT_MASKED_BIT_SHIFT 	0x12UL
#define DX_AXIM_ACE_CONST_AWADDR_NOT_MASKED_BIT_SIZE 	0x7UL
#define DX_AXIM_ACE_CONST_AWLEN_VAL_BIT_SHIFT 	0x19UL
#define DX_AXIM_ACE_CONST_AWLEN_VAL_BIT_SIZE 	0x4UL
#define DX_AXIM_CACHE_PARAMS_REG_OFFSET 	0xBF0UL
#define DX_AXIM_CACHE_PARAMS_AWCACHE_LAST_BIT_SHIFT 	0x0UL
#define DX_AXIM_CACHE_PARAMS_AWCACHE_LAST_BIT_SIZE 	0x4UL
#define DX_AXIM_CACHE_PARAMS_AWCACHE_BIT_SHIFT 	0x4UL
#define DX_AXIM_CACHE_PARAMS_AWCACHE_BIT_SIZE 	0x4UL
#define DX_AXIM_CACHE_PARAMS_ARCACHE_BIT_SHIFT 	0x8UL
#define DX_AXIM_CACHE_PARAMS_ARCACHE_BIT_SIZE 	0x4UL
#define DX_ADDR_AXIM_CTRL_REG_OFFSET 	0xBF4UL
#define DX_ADDR_AXIM_CTRL_VALUE_BIT_SHIFT 	0x0UL
#define DX_ADDR_AXIM_CTRL_VALUE_BIT_SIZE 	0x4UL

#endif	// __DX_CRYS_KERNEL_H__
