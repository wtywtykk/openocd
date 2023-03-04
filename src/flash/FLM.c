/***************************************************************************
 *   Copyright (C) 2021 by Tianyi Wang                                     *
 *   163.wty@163.com                                                       *
 *   Copyright (C) 2016 by Sysprogs                                        *
 *   sysprogs@sysprogs.com                                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <helper/binarybuffer.h>
#include <target/algorithm.h>
#include <target/armv7m.h>
#include <target/breakpoints.h>
#include <target/image.h>
#include "advanced_elf_image.h"
#include "nor/imp.h"
#include "FlashOS.h"

struct flm_file_info
{
	int probed;
	struct advanced_elf_image image;
	
	uint32_t EraseChip;
	uint32_t EraseSector;
	uint32_t Init;
	uint32_t ProgramPage;
	uint32_t UnInit;
	uint32_t Verify;
	uint32_t FlashDevice;
	
	struct FlashDevice FlashDeviceData;
	
	unsigned int stack_size;
	char *flm_file;
	
	uint32_t mem_start;
	uint32_t start;
	uint32_t size;
};

struct loaded_flm
{
	uint32_t sp;
	uint32_t finish_bkpt;
	uint32_t last_used_addr;
	struct target *target;
	struct flm_file_info *info;
};

static int call_flm_func(struct loaded_flm *flm, int timeout, uint32_t function, int32_t *result, int argc, ...);

static int flm_load(struct target *target, struct flm_file_info *flm_info, struct loaded_flm *flm)
{
	int retval;
	memset(flm, 0, sizeof(*flm));
	flm->target = target;
	flm->info = flm_info;
		
	uint32_t lastSectionEnd = flm_info->mem_start;
			
	for (int i = 0; i < flm_info->image.num_sections; i++)
	{
		if (!(flm_info->image.sections[i].sh_flags & 2 /*SHF_ALLOC*/))
			continue;		
		if (flm_info->image.sections[i].sh_type == 8 /* NOBITS */)
			continue;
		if (strcmp(advanced_elf_image_section_name(&flm_info->image, i), "DevDscr") == 0)
			continue;
		
		LOG_DEBUG("FLASH flm: loading section %s 0x%08x-0x%08x", advanced_elf_image_section_name(&flm_info->image, i), flm_info->image.sections[i].sh_addr, flm_info->image.sections[i].sh_addr + flm_info->image.sections[i].sh_size);
			
		uint8_t* pBuf = malloc(flm_info->image.sections[i].sh_size);
		size_t done;
		retval = advanced_elf_image_read_section(&flm_info->image, i, pBuf, flm_info->image.sections[i].sh_size, &done);
		if (retval == ERROR_OK)
			retval = target_write_memory(target, flm_info->mem_start + flm_info->image.sections[i].sh_addr, 4, flm_info->image.sections[i].sh_size / 4, pBuf);

		free(pBuf);
		if (retval != ERROR_OK || done != flm_info->image.sections[i].sh_size)
		{
			LOG_ERROR("Failed to read FLASH flm contents\n");
			return ERROR_FILEIO_OPERATION_FAILED;
		}
		
		uint32_t section_end = flm_info->mem_start + flm_info->image.sections[i].sh_addr + flm_info->image.sections[i].sh_size;
		if (lastSectionEnd < section_end)
		{
			lastSectionEnd = section_end;
		}
	}
	
	lastSectionEnd =  ((lastSectionEnd + 15) & ~15);
	flm->sp = lastSectionEnd + flm_info->stack_size;
	LOG_DEBUG("FLASH flm: placing the stack at 0x%08x-0x%08x", lastSectionEnd, lastSectionEnd + flm_info->stack_size);
	lastSectionEnd = flm->sp;
	
	uint8_t bkpt[16] = { 0x00, 0xbe, 0x00, 0xbe, 0x00, 0xbe, 0x00, 0xbe, 0x00, 0xbe, 0x00, 0xbe, 0x00, 0xbe, 0x00, 0xbe };
	flm->finish_bkpt = lastSectionEnd;
	flm->last_used_addr = flm->finish_bkpt + sizeof(bkpt);
	retval = target_write_memory(target, flm->finish_bkpt, 4, sizeof(bkpt) / 4, bkpt);
	if (retval != ERROR_OK)
	{
		LOG_ERROR("Failed to write finish breakpoint\n");
		return retval;
	}

	int32_t result;
	retval = call_flm_func(flm, flm->info->FlashDeviceData.toErase, flm->info->Init, &result, 3, flm->info->start, 8000000, 0);
	if (retval == ERROR_OK && result != 0)
	{
		LOG_ERROR("flm's Init() function returned error %d\n", result);
	}
	
	return retval;
}

static int flm_unload(struct loaded_flm *flm)
{	
	if (!flm->target)
		return ERROR_OK;
	
	int32_t result;
	int retval = call_flm_func(flm, flm->info->FlashDeviceData.toErase, flm->info->UnInit, &result, 0);
	if (retval == ERROR_OK && result != 0)
	{
		LOG_ERROR("flm's UnInit() function returned error %d\n", result);
		retval = ERROR_FLASH_BANK_INVALID;
	}
		
	return retval;
}

/* flash bank <name> flm <base> <size> 0 0 <target#> <flm ELF file> <memory base> [stack size = 512]
 */
FLASH_BANK_COMMAND_HANDLER(flm_file_info_command)
{
	struct flm_file_info *info;
	int retval;

	if (CMD_ARGC < 7)
		return ERROR_COMMAND_SYNTAX_ERROR;
	
	unsigned stackSize = 512;
	if (CMD_ARGC >= 9)
	{
		COMMAND_PARSE_NUMBER(uint, CMD_ARGV[8], stackSize);
	}
	
	info = malloc(sizeof(struct flm_file_info));
	memset(info, 0, sizeof(struct flm_file_info));
	
	COMMAND_PARSE_NUMBER(uint, CMD_ARGV[1], info->start);
	COMMAND_PARSE_NUMBER(uint, CMD_ARGV[2], info->size);
	COMMAND_PARSE_NUMBER(uint, CMD_ARGV[7], info->mem_start);
	
	const char *URL = CMD_ARGV[6];
	
	retval = advanced_elf_image_open(&info->image, URL);
	if (retval != ERROR_OK)
		return retval;
		
	info->EraseChip = advanced_elf_image_find_symbol(&info->image, "EraseChip");
	info->EraseSector = advanced_elf_image_find_symbol(&info->image, "EraseSector");
	info->Init = advanced_elf_image_find_symbol(&info->image, "Init");
	info->ProgramPage = advanced_elf_image_find_symbol(&info->image, "ProgramPage");
	info->UnInit = advanced_elf_image_find_symbol(&info->image, "UnInit");
	info->Verify = advanced_elf_image_find_symbol(&info->image, "Verify");
	info->FlashDevice = advanced_elf_image_find_symbol(&info->image, "FlashDevice");
	
	if (!(info->EraseChip && info->EraseSector && info->Init && info->ProgramPage && info->UnInit && info->FlashDevice))
	{
		LOG_ERROR("%s: invalid FLASH flm. Missing one or more critical functions.", URL);
		return ERROR_IMAGE_FORMAT_ERROR;
	}
	
	uint32_t flash_data_section = advanced_elf_image_find_section(&info->image, info->FlashDevice);
	if (flash_data_section == 0xFFFFFFFF)
	{
		LOG_ERROR("Unable to find section for FlashData");
		return ERROR_IMAGE_FORMAT_ERROR;
	}
		
	size_t flash_data_size = 0;
	retval = advanced_elf_image_read_section_offset(&info->image, flash_data_section, info->FlashDevice - info->image.sections[flash_data_section].sh_addr, &info->FlashDeviceData, sizeof(info->FlashDeviceData), &flash_data_size);
	if (retval != ERROR_OK || sizeof(info->FlashDeviceData) != flash_data_size)
	{
		LOG_ERROR("Unable to read FlashData or incorrect size");
		return ERROR_IMAGE_FORMAT_ERROR;
	}
	
	if (info->start != info->FlashDeviceData.DevAdr)
	{
		LOG_ERROR("base addr 0x%X doesn't match FLM base addr 0x%X", info->start , info->FlashDeviceData.DevAdr);
		return ERROR_FAIL;
	}
	if (info->size != info->FlashDeviceData.szDev)
	{
		LOG_ERROR("size 0x%X doesn't match FLM size 0x%X", info->size, info->FlashDeviceData.szDev);
		return ERROR_FAIL;
	}
  
	info->EraseChip +=	info->mem_start;
	info->EraseSector += info->mem_start;
	info->Init += info->mem_start;
	info->ProgramPage += info->mem_start;
	info->UnInit +=	info->mem_start;
	info->Verify += info->mem_start;
	info->FlashDevice += info->mem_start;
	
	info->stack_size = stackSize;
	bank->driver_priv = info;
	info->probed = 0;
	info->flm_file = strdup(URL);

	return ERROR_OK;
}

int flm_write_block(struct loaded_flm *loaded_flm, uint32_t offset, const uint8_t *buffer, uint32_t size)
{
	int retval = target_write_memory(loaded_flm->target, loaded_flm->last_used_addr, 4, size / 4, buffer);
	if (retval != ERROR_OK)
		return retval;
	if (size & 3)
	{
		retval = target_write_memory(loaded_flm->target, loaded_flm->last_used_addr + (size & ~3), 1, size & 3, buffer + (size & ~3));
		if (retval != ERROR_OK)
			return retval;
	}
	
	int32_t result = 0;
	retval = call_flm_func(loaded_flm, loaded_flm->info->FlashDeviceData.toProg, loaded_flm->info->ProgramPage, &result, 3, loaded_flm->info->start + offset, size, loaded_flm->last_used_addr);
	if (result != 0)
		return ERROR_FAIL;
	return result;
}

static int flm_write(struct flash_bank *bank,
	const uint8_t *buffer,
	uint32_t offset,
	uint32_t count)
{
	struct target *target = bank->target;
	struct flm_file_info *flm_info = bank->driver_priv;
	struct loaded_flm loaded_flm;
	
	uint32_t sector = 0;
	for (; sector < bank->num_sectors; sector++)
		if (bank->sectors[sector].offset + bank->sectors[sector].size > offset)
			break;
	
	int retval = flm_load(target, flm_info, &loaded_flm);
	if (retval == ERROR_OK)
	{
		uint32_t done = 0;
		while (done < count)
		{
			if (sector >= bank->num_sectors || bank->sectors[sector].offset > offset + done || bank->sectors[sector].offset + bank->sectors[sector].size < offset + done)
			{
				LOG_ERROR("flm writing address is not within any sectors");
				return ERROR_FAIL;
			}			
			
			uint32_t block = count - done;
			if (block > flm_info->FlashDeviceData.szPage)
				block = flm_info->FlashDeviceData.szPage;
			if (offset + done + block > bank->sectors[sector].offset + bank->sectors[sector].size)
				block = bank->sectors[sector].offset + bank->sectors[sector].size - offset - done;

			retval = flm_write_block(&loaded_flm, offset + done, buffer + done, block);
			if (retval != ERROR_OK)
				break;
				
			if (target->report_flash_progress)
				report_flash_progress("flash_write_progress", bank->base + offset + done, bank->base + offset + done + block, bank->name);

			done += block;
			if (offset + done >= bank->sectors[sector].offset + bank->sectors[sector].size)
				sector++;
		}
		flm_unload(&loaded_flm);
	}
	
	return retval;
}

static int call_flm_func(struct loaded_flm *flm, int timeout, uint32_t function, int32_t *result, int argc, ...)
{
	uint32_t sp = (flm->sp - 4) & ~3;
	const int r0ParamIndex = 2;
	char *arg_reg_names[] = { "r0", "r1", "r2", "r3" };
	
	struct reg_param reg_params[3 + 4];
	init_reg_param(&reg_params[0], "sp", 32, PARAM_IN_OUT);
	init_reg_param(&reg_params[1], "lr", 32, PARAM_IN_OUT); //ARM-specific!
	init_reg_param(&reg_params[r0ParamIndex], arg_reg_names[0], 32, PARAM_IN_OUT); //ARM-specific!
	buf_set_u32(reg_params[1].value, 0, 32, flm->finish_bkpt | 1); // thumb code
	int reg_param_count = r0ParamIndex;
	
	sp -= 4;
	
	va_list ap;
	va_start(ap, argc);
	for (int arg = 0; arg < argc; arg++)
	{
		uint32_t argVal = va_arg(ap, uint32_t);
		if ((unsigned)arg >= (sizeof(arg_reg_names) / sizeof(arg_reg_names[0])))
		{
			sp -= 4;
			target_write_memory(flm->target, sp, 4, 1, (uint8_t *)&argVal);
		}
		else 
		{
			if (arg == 0)
				reg_params[r0ParamIndex].direction = PARAM_IN_OUT;
			else
			{
				init_reg_param(&reg_params[r0ParamIndex + arg], arg_reg_names[arg], 32, PARAM_IN_OUT);
			}
			reg_param_count = r0ParamIndex + arg + 1;
			
			buf_set_u32(reg_params[r0ParamIndex + arg].value, 0, 32, argVal);
		}
			
	}
	va_end(ap);
	
	if (argc == 0)
		reg_param_count = r0ParamIndex + 1;
	
	buf_set_u32(reg_params[0].value, 0, 32, sp);
	//int bp = breakpoint_add(flm->target, flm->finish_bkpt, 2, BKPT_SOFT);
	//(void)bp;
		
	struct armv7m_algorithm armv7m_info;
	armv7m_info.common_magic = ARMV7M_COMMON_MAGIC;
	armv7m_info.core_mode = ARM_MODE_THREAD;

	int retval = target_run_algorithm(flm->target, 0, NULL, reg_param_count, reg_params, function, flm->finish_bkpt, timeout, &armv7m_info);
	//breakpoint_remove(flm->target, flm->finish_bkpt);
	
	if (retval == ERROR_OK && result)
		*result = (int32_t)buf_get_u32(reg_params[r0ParamIndex].value, 0, 32);
	
	for (int i = 0; i < reg_param_count; i++)
		destroy_reg_param(&reg_params[i]);
	
	return retval;
}

static int flm_probe(struct flash_bank *bank)
{
	struct flm_file_info *flm_info = bank->driver_priv;
	
	flm_info->probed = 1;

	bank->base = flm_info->start;
	bank->size = flm_info->size;
	bank->num_sectors = 0;
	
	for (size_t i = 0; i < SECTOR_NUM; i++)
	{
		if ((i == SECTOR_NUM - 1) || (flm_info->FlashDeviceData.sectors[i + 1].szSector == 0xFFFFFFFF && flm_info->FlashDeviceData.sectors[i + 1].AddrSector == 0xFFFFFFFF))
		{
			bank->num_sectors += (bank->size - flm_info->FlashDeviceData.sectors[i].AddrSector) / flm_info->FlashDeviceData.sectors[i].szSector;
			break;
		}
		else
		{
			bank->num_sectors += (flm_info->FlashDeviceData.sectors[i + 1].AddrSector - flm_info->FlashDeviceData.sectors[i].AddrSector) / flm_info->FlashDeviceData.sectors[i].szSector;
		}
	}
	
	bank->sectors = malloc(sizeof(struct flash_sector) * bank->num_sectors);
	memset(bank->sectors, 0, sizeof(struct flash_sector) * bank->num_sectors);
		
	uint32_t sector_index = 0;
	for (size_t i = 0; i < SECTOR_NUM; i++)
	{
		if ((i == SECTOR_NUM - 1) || (flm_info->FlashDeviceData.sectors[i + 1].szSector == 0xFFFFFFFF && flm_info->FlashDeviceData.sectors[i + 1].AddrSector == 0xFFFFFFFF))
		{
			uint32_t sector_block_count = (bank->size - flm_info->FlashDeviceData.sectors[i].AddrSector) / flm_info->FlashDeviceData.sectors[i].szSector;
			for (uint32_t j = 0; j < sector_block_count; j++)
			{
				bank->sectors[sector_index].offset = flm_info->FlashDeviceData.sectors[i].AddrSector + j * flm_info->FlashDeviceData.sectors[i].szSector;
				bank->sectors[sector_index].size = flm_info->FlashDeviceData.sectors[i].szSector;
				sector_index++;
			}
			break;
		}
		else
		{
			uint32_t sector_block_count = (flm_info->FlashDeviceData.sectors[i + 1].AddrSector  - flm_info->FlashDeviceData.sectors[i].AddrSector) / flm_info->FlashDeviceData.sectors[i].szSector;
			for (uint32_t j = 0; j < sector_block_count; j++)
			{
				bank->sectors[sector_index].offset = flm_info->FlashDeviceData.sectors[i].AddrSector + j * flm_info->FlashDeviceData.sectors[i].szSector;
				bank->sectors[sector_index].size = flm_info->FlashDeviceData.sectors[i].szSector;
				sector_index++;
			}
		}
	}

	return ERROR_OK;
}

static int flm_auto_probe(struct flash_bank *bank)
{
	struct flm_file_info *flm_info = bank->driver_priv;
	if (flm_info->probed)
		return ERROR_OK;
	return flm_probe(bank);
}

static int get_flm_info(struct flash_bank *bank, struct command_invocation *cmd)
{
	struct flm_file_info *flm_info = bank->driver_priv;
	
	command_print(cmd, "FLM-managed FLASH\r\nFLM file: %s", flm_info->flm_file);
	command_print(cmd, "Start address: 0x%x", flm_info->FlashDeviceData.DevAdr);
	command_print(cmd, "Description: %s", flm_info->FlashDeviceData.DevName);
	return ERROR_OK;
}

static int flm_erase(struct flash_bank *bank, unsigned first, unsigned last)
{
	struct target *target = bank->target;
	struct flm_file_info *flm_info = bank->driver_priv;
	struct loaded_flm loaded_flm;
	
	int retval = flm_load(target, flm_info, &loaded_flm);
	if (retval == ERROR_OK)
	{
		while (first <= last)
		{
			int32_t result;
			retval = call_flm_func(&loaded_flm, flm_info->FlashDeviceData.toErase, flm_info->EraseSector, &result, 1, bank->base + bank->sectors[first].offset);
			if (retval != ERROR_OK)
				break;
			if (result != 0)
			{
				LOG_ERROR("EraseSector() returned %d", result);
				retval = ERROR_FLASH_BANK_INVALID;
				break;
			}
			
			if (target->report_flash_progress)
				report_flash_progress("flash_erase_progress", bank->base + bank->sectors[first].offset, bank->base + bank->sectors[first + result - 1].offset + bank->sectors[first + result - 1].size, bank->name);
			
			first++;
		}
		flm_unload(&loaded_flm);
	}
	
	return retval;
}

COMMAND_HANDLER(flm_handle_mass_erase_command)
{
	if (CMD_ARGC < 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	struct flash_bank *bank;
	int retval = CALL_COMMAND_HANDLER(flash_command_get_bank, 0, &bank);
	if (ERROR_OK != retval)
		return retval;

	struct target *target = bank->target;
	struct flm_file_info *flm_info = bank->driver_priv;
	struct loaded_flm loaded_flm;
	
	retval = flm_load(target, flm_info, &loaded_flm);
	if (retval == ERROR_OK)
	{
		int32_t result;
		retval = call_flm_func(&loaded_flm, flm_info->FlashDeviceData.toErase, flm_info->EraseChip, &result, 0);
		if (retval == ERROR_OK && result != 0)
		{
			retval = ERROR_FAIL;
				
		}
		flm_unload(&loaded_flm);
	}
	
	if (retval == ERROR_OK)
	{
		command_print(CMD, "flm mass erase complete");
	}
	else
	{
		command_print(CMD, "flm mass erase failed");
	}
	return retval;
}

static const struct command_registration flm_exec_command_handlers[] = {
{
	.name = "mass_erase",
	.handler = flm_handle_mass_erase_command,
	.mode = COMMAND_EXEC,
	.usage = "bank_id",
	.help = "Erase entire flash device.",
},
	COMMAND_REGISTRATION_DONE
};

static const struct command_registration flm_command_handlers[] = {
{
	.name = "flm",
	.mode = COMMAND_ANY,
	.help = "flm flash command group",
	.usage = "",
	.chain = flm_exec_command_handlers,
},
	COMMAND_REGISTRATION_DONE
};

struct flash_driver flm_flash = {
	.name = "flm",
	.commands = flm_command_handlers,
	.flash_bank_command = flm_file_info_command,
	.erase = flm_erase,
	.write = flm_write,
	.read = default_flash_read,
	.probe = flm_probe,
	.auto_probe = flm_auto_probe,
	.erase_check = default_flash_blank_check,
	.info = get_flm_info,
	.protect_check = NULL,
	.protect = NULL
};
