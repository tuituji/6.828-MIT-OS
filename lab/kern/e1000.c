#include <kern/e1000.h>
#include <kern/pmap.h>
#include <inc/string.h>
// LAB 6: Your driver code here

// please refer to kern/lapic.c
// use a global variable to store the mmaped address

//volatile uint32_t *e1000_mmio;

// refer to the data-sheet  14.5
// the mem should be 16 bytes aligned

struct tx_desc tx_desc_list[E1000_TXDESC_NUM] __attribute__((aligned(16)));
struct tx_pktbuf tx_pktbufs[E1000_TXDESC_NUM];

struct rx_desc rx_desc_list[E1000_RXDESC_NUM] __attribute__((aligned(16)));
struct rx_pktbuf rx_pktbufs[E1000_RXDESC_NUM];

static void e1000_init(struct pci_func *pcif)
{
	// init mem
	int i;
	uint32_t val, val1; 
	memset(tx_desc_list, 0x0, sizeof(tx_desc_list));
	memset(tx_pktbufs, 0x0, sizeof(tx_pktbufs));
	for (i = 0; i < E1000_TXDESC_NUM; ++i) {
		tx_desc_list[i].addr = PADDR(tx_pktbufs[i].buffer);
		tx_desc_list[i].status = E1000_TXD_STAT_DD;
	}
	
	// init the hw
	// refer to 14.5 of datasheet
	e1000_writel(E1000_TDBAL, PADDR(tx_desc_list));
	e1000_writel(E1000_TDBAH, 0x0);
	e1000_writel(E1000_TDLEN, sizeof(tx_desc_list));
	e1000_writel(E1000_TDH, 0x0);
	e1000_writel(E1000_TDT, 0x0);

	// initialize the Transmit Control Register (TCTL)
	val = e1000_readl(E1000_TCTL);
	val |= E1000_TCTL_EN;
	val |= E1000_TCTL_PSP;
	val &= ~E1000_TCTL_CT;
	val |= 0x10 << 4; 			
	val &= ~E1000_TCTL_COLD;
	val |= 0x40 << 12;
	e1000_writel(E1000_TCTL, val);

	// Program the Transmit IPG (TIPG) register w
	val = 0x0;
	val |= 0x6 << 20;	// IPGR2
	val |= 0x4 << 10;	// IPGR1
	val |= 0xA;			// IPGR
	e1000_writel(E1000_TIPG, val);

	// init receive
	memset(rx_desc_list, 0x0, sizeof(rx_desc_list));
	memset(rx_pktbufs, 0x0, sizeof(rx_pktbufs));
	for (i = 0 ; i < E1000_RXDESC_NUM; ++i) {
		rx_desc_list[i].addr = PADDR(rx_pktbufs[i].buffer);
	}

	val = 0x0;
	e1000_writel(E1000_EERD, val); // address 
	val |= E1000_EERD_START;
	e1000_writel(E1000_EERD, val);// to start
	while ((e1000_readl(E1000_EERD) & E1000_EERD_DONE) != E1000_EERD_DONE);
	val = e1000_readl(E1000_EERD);
	e1000_writel(E1000_RAL, val >> 16);
	
	val = 0x1 << 8;
	e1000_writel(E1000_EERD, val);
	val |= E1000_EERD_START;
	e1000_writel(E1000_EERD, val);
	while ((e1000_readl(E1000_EERD) & E1000_EERD_DONE) != E1000_EERD_DONE);
	val = e1000_readl(E1000_EERD);
	val1 = e1000_readl(E1000_RAL) | (val & 0xffff0000);
	e1000_writel(E1000_RAL, val1);
	
	val = 0x2 << 8;
	e1000_writel(E1000_EERD, val);
	val |= E1000_EERD_START;
	e1000_writel(E1000_EERD, val);
	while ((val = e1000_readl(E1000_EERD) & E1000_EERD_DONE) 
		!= E1000_EERD_DONE) {
		cprintf("val 0x%x\n", val)	;
	}
	val = e1000_readl(E1000_EERD);
	e1000_writel(E1000_RAH, val >> 16);
	
	cprintf("come to 4");
	val = e1000_readl(E1000_RAH);
	val |= 0x1 << 31;
	e1000_writel(E1000_RAH, val);
	
	e1000_writel(E1000_RDBAL, PADDR(rx_desc_list));
	e1000_writel(E1000_RDBAL, 0x0);
	
	e1000_writel(E1000_RDLEN, sizeof(rx_desc_list));
	
	e1000_writel(E1000_RDH, 0x0);
	e1000_writel(E1000_RDT, 0x0);
	
	val = e1000_readl(E1000_RCTL);
	val |= E1000_RCTL_EN;
	val &= ~E1000_RCTL_LPE;
	val &= ~E1000_RCTL_LBM;
	val &= ~E1000_RCTL_RDMTS;
	val &= ~E1000_RCTL_MO;
	val |= E1000_RCTL_BAM;
	val &= ~E1000_RCTL_SZ;
	val |= E1000_RCTL_SECRC;
	e1000_writel(E1000_RCTL, val);
}


int e1000_attach(struct pci_func *pcif)
{
	int ret = 0;
	pci_func_enable(pcif);

	boot_map_region(kern_pgdir, E1000_MMIO, pcif->reg_size[0], 
			pcif->reg_base[0], PTE_P | PTE_W | PTE_PCD | PTE_PWT);
	e1000_mmio = (uint32_t*) E1000_MMIO;
//	ret = e1000_readl(E1000_STATUS);
	assert(e1000_readl(E1000_STATUS) == 0x80080783);
	cprintf("e1000 status register: 0x%x\n", e1000_readl(E1000_STATUS));
	e1000_init(pcif);

	return ret;
}

int e1000_tx(uint8_t* data, uint32_t len)
{
	// now do not consider multiple packet
	if (len > TX_PKTBUF_SIZE) return -1;

	uint32_t tdt = e1000_readl(E1000_TDT); // the index in the desc_list
	if ((tx_desc_list[tdt].status & E1000_TXD_STAT_DD) != E1000_TXD_STAT_DD )	
		return -1;
	// refer to Table 3-10. Transmit Command (TDESC.CMD) Layout in datasheet
	tx_desc_list[tdt].status &= ~ E1000_TXD_STAT_DD;
	tx_desc_list[tdt].cmd = E1000_TXD_CMD_EOP;
	
	e1000_writel(E1000_TDT, (tdt + 1) % E1000_TXDESC_NUM);
	return 0;
}

int e1000_rx(uint8_t *data, uint32_t len)
{
	uint32_t rdt;

	rdt = e1000_readl(E1000_RDT);
	if (rx_desc_list[rdt].status & E1000_RXD_STAT_DD) {
		assert(!(rx_desc_list[rdt].status & E1000_RXD_STAT_EOP));
		assert(len >= rx_desc_list[rdt].length);
		memmove(data, rx_pktbufs[rdt].buffer, len);
		rx_desc_list[rdt].status &= ~E1000_RXD_STAT_DD;
		rx_desc_list[rdt].status &= ~E1000_RXD_STAT_EOP;
		e1000_writel(E1000_RDT, (rdt + 1) % E1000_RXDESC_NUM);
		return rx_desc_list[rdt].length;
	}
	return -1;
}
