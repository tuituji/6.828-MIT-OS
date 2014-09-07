#ifndef JOS_KERN_E1000_H
#define JOS_KERN_E1000_H

#include <kern/pci.h>

#define E1000_VENDOR 			0x8086
#define E1000_DEVICE 			0x100e

#define E1000_MMIO KSTACKTOP
#define E1000_TXDESC_NUM 		128
#define E1000_RXDESC_NUM 		128
#define TX_PKTBUF_SIZE 			1518
#define RX_PKTBUF_SIZE			2048
#define E1000_STATUS   0x00008  /* Device Status - RO */
#define E1000_TDBAL    0x03800  /* TX Descriptor Base Address Low - RW */
#define E1000_TDBAH    0x03804  /* TX Descriptor Base Address High - RW */
#define E1000_TDLEN    0x03808  /* TX Descriptor Length - RW */
#define E1000_TDH      0x03810  /* TX Descriptor Head - RW */
#define E1000_TDT      0x03818  /* TX Descripotr Tail - RW */

#define E1000_TXD_CMD_RS     0x00000008 /* Report Status */
#define E1000_TXD_CMD_EOP    0x00000001 /* End of Packet */
#define E1000_TXD_STAT_DD    0x00000001 /* Descriptor Done */
        


#define E1000_TCTL     0x00400  /* TX Control - RW */


/* Transmit Control */
#define E1000_TCTL_RST    0x00000001    /* software reset */
#define E1000_TCTL_EN     0x00000002    /* enable tx */
#define E1000_TCTL_BCE    0x00000004    /* busy check enable */
#define E1000_TCTL_PSP    0x00000008    /* pad short packets */
#define E1000_TCTL_CT     0x00000ff0    /* collision threshold */
#define E1000_TCTL_COLD   0x003ff000    /* collision distance */
#define E1000_TCTL_SWXOFF 0x00400000    /* SW Xoff transmission */
#define E1000_TCTL_PBE    0x00800000    /* Packet Burst Enable */
#define E1000_TCTL_RTLC   0x01000000    /* Re-transmit on late collision */
#define E1000_TCTL_NRTU   0x02000000    /* No Re-transmit on underrun */
#define E1000_TCTL_MULR   0x10000000    /* Multiple request support */


#define E1000_TIPG     0x00410  /* TX Inter-packet gap -RW */


#define E1000_EERD     0x00014  /* EEPROM Read - RW */
#define E1000_EERD_START 0x01
#define E1000_EERD_DONE  0x10
#define E1000_RDBAL    0x02800  /* RX Descriptor Base Address Low - RW */
#define E1000_RDBAH    0x02804  /* RX Descriptor Base Address High - RW */
#define E1000_RDLEN    0x02808  /* RX Descriptor Length - RW */
#define E1000_RDH      0x02810  /* RX Descriptor Head - RW */
#define E1000_RDT      0x02818  /* RX Descriptor Tail - RW */
#define E1000_RAL      0x05400  /* Receive Address Low - RW */
#define E1000_RAH      0x05404  /* Receive Address High - RW */
#define E1000_RCTL     0x00100  /* RX Control - RW */

#define E1000_RCTL     0x00100  /* RX Control - RW */
#define E1000_RCTL_EN             0x00000002    /* enable */
#define E1000_RCTL_LPE            0x00000020    /* long packet enable */
#define E1000_RCTL_LBM            0x000000C0    /* loopback mode */
#define E1000_RCTL_RDMTS          0x00000300    /* rx min threshold size */
#define E1000_RCTL_MO             0x00003000    /* multicast offset shift */
#define E1000_RCTL_BAM            0x00008000    /* broadcast enable */
#define E1000_RCTL_SZ             0x00030000    /* rx buffer size */
#define E1000_RCTL_SECRC          0x04000000    /* Strip Ethernet CRC */

#define E1000_RXD_STAT_DD       0x01    /* Descriptor Done */
#define E1000_RXD_STAT_EOP      0x02    /* End of Packet */


volatile uint32_t *e1000_mmio;

struct tx_desc {
	uint64_t addr;
	uint16_t length;
	uint8_t cso;
	uint8_t cmd;
	uint8_t status;
	uint8_t css;
	uint16_t special;
}__attribute__((packed));

struct rx_desc {
	uint64_t addr;
	uint16_t length;
	uint16_t chksum;
	uint8_t status;
	uint8_t errors; 
	uint16_t special;
} __attribute__((packed));

struct tx_pktbuf {
	uint8_t buffer[TX_PKTBUF_SIZE];
}__attribute__ ((packed));

struct rx_pktbuf {
	uint8_t buffer[RX_PKTBUF_SIZE];
}__attribute__ ((packed));

#define  e1000_readl(reg) (e1000_mmio[(reg) >>2])
#define  e1000_writel(reg, val) \
			do { e1000_mmio[(reg) >> 2] = (val); } while (0)

int e1000_attach(struct pci_func *pcif);
int e1000_tx(uint8_t* data, uint32_t len);
int e1000_rx(uint8_t* data, uint32_t len);

#endif	// JOS_KERN_E1000_H

