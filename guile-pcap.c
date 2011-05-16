/* Copyright (C) 2003 David J. Lambert.
   Copyright (C) 1995, 1996, 1997, 2000, 2001 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
   USA.  */


#include <libguile.h>
#include <pcap.h>

/* XXX This mess of includes is from guile-1.6.1's socket.c file. */
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#else
#include <sys/socket.h>
#ifdef HAVE_UNIX_DOMAIN_SOCKETS
#include <sys/un.h>
#endif
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#endif

#define SPCAP_PCAP_SMOBP(x) SCM_SMOB_PREDICATE (spcap_pcap_smob_tag, (x))
#define SPCAP_SMOB2PCAP(x) ((pcap_t *) SCM_SMOB_DATA (x))

#define SPCAP_PCAP_DUMPER_SMOBP(x) SCM_SMOB_PREDICATE (spcap_pcap_dumper_smob_tag, (x))
#define SPCAP_SMOB2PCAP_DUMPER(x) ((pcap_dumper_t *) SCM_SMOB_DATA (x))

#define SPCAP_BPF_PROGRAM_SMOBP(x) SCM_SMOB_PREDICATE (spcap_bpf_program_smob_tag, (x))
#define SPCAP_SMOB2BPF_PROGRAM(x) ((struct bpf_program *) SCM_SMOB_DATA (x))

static size_t spcap_pcap_smob_free (SCM);
static int spcap_pcap_smob_print (SCM, SCM, scm_print_state *);
static size_t spcap_pcap_dumper_smob_free (SCM);
static int spcap_pcap_dumper_smob_print (SCM, SCM, scm_print_state *);
static size_t spcap_bpf_program_smob_free (SCM);
static int spcap_bpf_program_smob_print (SCM, SCM, scm_print_state *);
static SCM scm_addr_vector (const struct sockaddr *, const char *);
static SCM linktype2scm (int);
static int scm2linktype (SCM);
static SCM spcap_c2scm (const u_char *, const struct pcap_pkthdr *);
static void spcap_metacallback (u_char *, const struct pcap_pkthdr *, const u_char *);
static SCM make_u8_vector (const unsigned char *, int);

/* This is in the SRFI-4 library.  */
extern SCM scm_make_u8vector (SCM, SCM);

/* The SMOB type tag for pcap_t's.  */
static scm_t_bits spcap_pcap_smob_tag;

/* The SMOB type tag for pcap_dumper_t's.  */
static scm_t_bits spcap_pcap_dumper_smob_tag;

/* The SMOB type tag for struct bpf_program's.  */
static scm_t_bits spcap_bpf_program_smob_tag;

/* Used as key when any of the pcap functions returns an error.  */
static SCM spcap_error_symbol;

/* The symbol for indicating an interface is a loopback one.  */
static SCM spcap_if_loopback_symbol;

/* This deals with the conversion between C defines for datalink types
   and equivalent Scheme symbols.  */
struct lookup
{
    int number;
    char *name;
    SCM symbol;
};

struct lookup linktype_table[] = {
    {DLT_NULL, "DLT_NULL", 0},
    {DLT_EN10MB, "DLT_EN10MB", 0},
    {DLT_IEEE802, "DLT_IEEE802", 0},
    {DLT_ARCNET, "DLT_ARCNET", 0},
    {DLT_SLIP, "DLT_SLIP", 0},
    {DLT_PPP, "DLT_PPP", 0},
    {DLT_FDDI, "DLT_FDDI", 0},
    {DLT_ATM_RFC1483, "DLT_ATM_RFC1483", 0},
    {DLT_RAW, "DLT_RAW", 0},
    {DLT_PPP_SERIAL, "DLT_PPP_SERIAL", 0},
    {DLT_PPP_ETHER, "DLT_PPP_ETHER", 0},
    {DLT_C_HDLC, "DLT_C_HDLC", 0},
    {DLT_IEEE802_11, "DLT_IEEE802_11", 0},
    {DLT_LOOP, "DLT_LOOP", 0},
    {DLT_LINUX_SLL, "DLT_LINUX_SLL", 0},
    {DLT_LTALK, "DLT_LTALK", 0}
};


/* Find the Scheme symbol for datalink type @var{c}.  Returns
   @code{#f} if there is none. */
static SCM
linktype2scm (int c)
{
    int i;
    
    for (i=0; i < (sizeof (linktype_table) / sizeof (struct lookup)); i++)
	if (c == linktype_table[i].number)
	    return scm_str2symbol (linktype_table[i].name);
    return SCM_BOOL_F;
}


/* Find the C value for the Scheme symbol for datalink type @var{s}.
   Returns @code{-1} if there is none. */
static int
scm2linktype (SCM s)
{
    int i;
    
    for (i=0; i < (sizeof (linktype_table) / sizeof (struct lookup)); i++)
	if (s == linktype_table[i].symbol)
	    return linktype_table[i].number;
    return -1;
}


/* A wrapper to allow Scheme procedures to be called from
   pcap_dispatch and pcap_loop.  */
static void
spcap_metacallback (u_char *callback, const struct pcap_pkthdr *pkthdr, const u_char *pkt)
{
    SCM s_callback = (SCM) callback;

    scm_call_1 (s_callback, spcap_c2scm (pkt, pkthdr));
}


/* Returns a nice list of SCM types from a raw packet @var{pkt} and
   its @var{pkthdr} metadata.  Returns @code{SCM_BOOL_F} if @var{pkt}
   is NULL. */
static SCM
spcap_c2scm (const u_char *pkt, const struct pcap_pkthdr *pkthdr)
{
    if (pkt == NULL)
	return SCM_BOOL_F;
    else
	return scm_list_4 (scm_cons (scm_ulong2num (pkthdr->ts.tv_sec),
				     SCM_MAKINUM (pkthdr->ts.tv_usec)),
			   SCM_MAKINUM (pkthdr->caplen), SCM_MAKINUM (pkthdr->len),
			   make_u8_vector (pkt, pkthdr->caplen));
}


static size_t
spcap_pcap_smob_free (SCM obj)
{
    pcap_t *pcap = SPCAP_SMOB2PCAP (obj);
    pcap_close (pcap);
    return 0;
}


static int
spcap_pcap_smob_print (SCM obj, SCM port, scm_print_state *state)
{
    char buf[20];
    
    sprintf (buf, "%x", (unsigned int) SPCAP_SMOB2PCAP (obj));
    scm_puts ("#<pcap ", port);
    scm_puts (buf, port);
    scm_puts (">", port);

    return 1;
}


static size_t
spcap_pcap_dumper_smob_free (SCM obj)
{
    pcap_dumper_t *dumper = SPCAP_SMOB2PCAP_DUMPER (obj);
    pcap_dump_close (dumper);
    return 0;
}


static int
spcap_pcap_dumper_smob_print (SCM obj, SCM port, scm_print_state *state)
{
    char buf[20];
    
    sprintf (buf, "%x", (unsigned int) SPCAP_SMOB2PCAP_DUMPER (obj));
    scm_puts ("#<pcap-dumper ", port);
    scm_puts (buf, port);
    scm_puts (">", port);

    return 1;
}


static size_t
spcap_bpf_program_smob_free (SCM obj)
{
    struct bpf_program *bpf_program = SPCAP_SMOB2BPF_PROGRAM (obj);
    pcap_freecode (bpf_program);
    scm_must_free (bpf_program);
    return 0;
}


static int
spcap_bpf_program_smob_print (SCM obj, SCM port, scm_print_state *state)
{
    char buf[20];
    
    sprintf (buf, "%x", (unsigned int) SPCAP_SMOB2BPF_PROGRAM (obj));
    scm_puts ("#<bpf-program ", port);
    scm_puts (buf, port);
    scm_puts (">", port);

    return 1;
}


SCM_DEFINE (spcap_compile, "pcap-compile", 4, 0, 0,
	    (SCM pcap, SCM str, SCM optimize, SCM netmask),
	    "Compiles @var{str} into a @code{bpf-program} object, and returns it.\n"
	    "If @var{optimize} is true, the filter will be optimized.\n"
	    "@var{netmask} is the netmask of the local network.")
#define FUNC_NAME s_spcap_compile
{
    int c_error;
    pcap_t *c_pcap;
    struct bpf_program *c_bpf_program;
    bpf_u_int32 c_netmask;
    
    SCM_ASSERT (SPCAP_PCAP_SMOBP (pcap), pcap, SCM_ARG1, FUNC_NAME);
    SCM_ASSERT (SCM_STRINGP (str), str, SCM_ARG2, FUNC_NAME);
    SCM_ASSERT (SCM_BOOLP (optimize), optimize, SCM_ARG3, FUNC_NAME);

    c_netmask = scm_num2ulong (netmask, SCM_ARG4, FUNC_NAME);
    c_pcap = SPCAP_SMOB2PCAP (pcap);
    c_bpf_program = scm_must_malloc (sizeof (struct bpf_program), "bpf-program");
    c_error = pcap_compile (c_pcap, c_bpf_program, 
			    SCM_STRING_CHARS (str), 
			    SCM_NFALSEP (optimize),
			    c_netmask);
    if (c_error == -1)
    {
	scm_must_free (c_bpf_program);
	scm_error (spcap_error_symbol, FUNC_NAME, pcap_geterr (c_pcap), SCM_EOL, SCM_EOL);
    }
    SCM_RETURN_NEWSMOB (spcap_bpf_program_smob_tag, c_bpf_program);
}
#undef FUNC_NAME


SCM_DEFINE (spcap_datalink, "pcap-datalink", 1, 0, 0,
	    (SCM pcap),
	    "Returns the type of link-layer type of @var{pcap}.\n"
	    "Return values are symbols, identical to the C defines:\n"
	    "@code{\'DLT_PPP}, @code{\'DLT_FDDI} etc.")
#define FUNC_NAME s_spcap_datalink
{
    int dl;
    pcap_t *c_pcap;
    SCM s;

    SCM_ASSERT (SPCAP_PCAP_SMOBP (pcap), pcap, SCM_ARG1, FUNC_NAME);
    
    c_pcap = SPCAP_SMOB2PCAP (pcap);
    dl = pcap_datalink (c_pcap);
    s = linktype2scm (dl);
    if (SCM_NFALSEP (s))
	return s;
    else
	scm_error (spcap_error_symbol, FUNC_NAME, "Unknown datalink type", SCM_EOL, SCM_EOL);
}
#undef FUNC_NAME


SCM_DEFINE (spcap_dispatch, "pcap-dispatch", 3, 0, 0,
	    (SCM pcap, SCM cnt, SCM callback),
	    "Collects packets from @var{pcap} and calls @var{callback} on each.\n"
	    "At most @var{cnt} packets will be processed, perhaps fewer.\n  If\n"
	    "@var{cnt} is @code{-1}, a bufferful (if live) or a fileful (if saved)\n"
	    "is processed en-masse. \n"
	    "@var{callback} should accept an argument like that returned by\n"
	    "@code{pcap-next}.  If @var{callback} is a @code{pcap-dumper}, the\n"
	    "C @code{pcap_dump} function will be used.\n"
	    "The number of packets processed is returned.")
#define FUNC_NAME s_spcap_dispatch
{
    int c_result;
    pcap_t * c_pcap;
    
    SCM_ASSERT (SPCAP_PCAP_SMOBP (pcap), pcap, SCM_ARG1, FUNC_NAME);
    SCM_ASSERT (SCM_INUMP (cnt), cnt, SCM_ARG2, FUNC_NAME);
    
    c_pcap = SPCAP_SMOB2PCAP (pcap);

    if (SPCAP_PCAP_DUMPER_SMOBP (callback))
	c_result = pcap_dispatch (c_pcap, scm_num2int (cnt, SCM_ARG2, FUNC_NAME),
				  pcap_dump,
				  (u_char *) SPCAP_SMOB2PCAP_DUMPER (callback));
    else if (scm_procedure_p (callback))
	c_result = pcap_dispatch (c_pcap, scm_num2int (cnt, SCM_ARG2, FUNC_NAME),
				  spcap_metacallback, (u_char *) callback);
    else
	SCM_WRONG_TYPE_ARG (SCM_ARG3, callback);
    
    scm_remember_upto_here_1 (pcap);

    if (c_result < 0)
	scm_error (spcap_error_symbol, FUNC_NAME, pcap_geterr (c_pcap), SCM_EOL, SCM_EOL);
    else
	return scm_int2num (c_result);
}
#undef FUNC_NAME


SCM_DEFINE (spcap_dump, "pcap-dump", 2, 0, 0,
	    (SCM form, SCM dumper),
	    "Outputs the pcap @var{form} to the @var{dumper} file opened with\n"
	    "@code{pcap-dumper-open}.")
#define FUNC_NAME s_spcap_dump
{
    struct pcap_pkthdr c_pkthdr;

    SCM_ASSERT ((scm_list_p (form)) &&
		(scm_ilength (form) == 4) &&
		(SCM_CONSP (SCM_CAR (form))) &&
		(scm_string_p (SCM_CADDDR (form))),
		form, SCM_ARG1, FUNC_NAME);
    SCM_ASSERT (SPCAP_PCAP_DUMPER_SMOBP (dumper), dumper, SCM_ARG2, FUNC_NAME);

    c_pkthdr.ts.tv_sec = scm_num2ulong (SCM_CAAR (form), SCM_ARG1, FUNC_NAME);
    c_pkthdr.ts.tv_usec = scm_num2ulong (SCM_CDAR (form), SCM_ARG1, FUNC_NAME);
    c_pkthdr.len = scm_num2int (SCM_CADR (form), SCM_ARG1, FUNC_NAME);
    c_pkthdr.caplen = scm_num2int (SCM_CADDR (form), SCM_ARG1, FUNC_NAME);

    pcap_dump ((u_char *) SPCAP_SMOB2PCAP_DUMPER (dumper),
	       &c_pkthdr, SCM_STRING_CHARS (SCM_CADDDR (form)));
	
    return SCM_UNSPECIFIED;    
}
#undef FUNC_NAME


SCM_DEFINE (spcap_dump_open, "pcap-dump-open", 2, 0, 0,
	    (SCM pcap, SCM filename),
	    "Returns an object allowing output to @var{filename}.\n"
	    "If @var{filename} is @code{\"-\"}, output goes to stdout.")
#define FUNC_NAME s_spcap_dump_open
{
    pcap_t *c_pcap;
    pcap_dumper_t *c_dumper;

    SCM_ASSERT (SPCAP_PCAP_SMOBP (pcap), pcap, SCM_ARG1, FUNC_NAME);
    SCM_ASSERT (SCM_STRINGP (filename), filename, SCM_ARG2, FUNC_NAME);
    
    c_pcap = SPCAP_SMOB2PCAP (pcap);
    c_dumper = pcap_dump_open (c_pcap, SCM_STRING_CHARS (filename));
    if (c_dumper)
	SCM_RETURN_NEWSMOB (spcap_pcap_dumper_smob_tag, c_dumper);
    else
	scm_error (spcap_error_symbol, FUNC_NAME, pcap_geterr (c_pcap), SCM_EOL, SCM_EOL);
}
#undef FUNC_NAME


SCM_DEFINE (spcap_fileno, "pcap-fileno", 1, 0, 0,
	    (SCM pcap),
	    "Obtain the Unix file number associated with the packet capture.\n"
	    "Returns @code{#f} if there is no file.")
#define FUNC_NAME s_spcap_fileno
{
    pcap_t *c_pcap;
    int c_fileno;

    SCM_ASSERT (SPCAP_PCAP_SMOBP (pcap), pcap, SCM_ARG1, FUNC_NAME);
    
    c_pcap = SPCAP_SMOB2PCAP (pcap);
    c_fileno = pcap_fileno (c_pcap);
    if (c_fileno == -1)
	return SCM_BOOL_F;
    else
	return (SCM_MAKINUM (c_fileno));
}
#undef FUNC_NAME


SCM_DEFINE (spcap_findalldevs, "pcap-findalldevs", 0, 0, 0,
	    (),
	    "Returns a list of interfaces on the current machine.\n"
	    "Not all interfaces may be openable by the calling process.\n"
	    "Each element of the result is a list of the interface's name,\n"
	    "description, list of sockaddr vectors, and a list of flags.\n"
	    "Each sockaddr vector comprises address, netmask, broadcast address,\n"
	    "and destination socket address.  The only flag is \n"
	    "the symbol @code{PCAP_IF_LOOPBACK}.")
#define FUNC_NAME s_spcap_findalldevs
{
    pcap_if_t *c_allifaces, *c_iface;
    pcap_addr_t *c_addr;
    char errbuf[PCAP_ERRBUF_SIZE];
    SCM allifaces, iface, addrs;
    SCM name, desc, flags;
    SCM addr, netmask, broadaddr, dstaddr;

    if (pcap_findalldevs (&c_allifaces, errbuf))
	scm_error (spcap_error_symbol, FUNC_NAME, errbuf, SCM_EOL, SCM_EOL);
    
    allifaces = SCM_EOL;
    for (c_iface = c_allifaces; c_iface; c_iface = c_iface->next)
    {
	name = scm_makfrom0str (c_iface->name);
	desc = scm_makfrom0str (c_iface->description);

	for (addrs = SCM_EOL, c_addr = c_iface->addresses; c_addr; c_addr = c_addr->next)
	{
	    addr = netmask = broadaddr = dstaddr = SCM_BOOL_F;
	    if (c_addr->addr)
		addr = scm_addr_vector (c_addr->addr, FUNC_NAME);
	    if (c_addr->netmask)
		netmask = scm_addr_vector (c_addr->netmask, FUNC_NAME);
	    if (c_addr->broadaddr)
		broadaddr = scm_addr_vector (c_addr->broadaddr, FUNC_NAME);
	    if (c_addr->dstaddr)
		addr = scm_addr_vector (c_addr->dstaddr, FUNC_NAME);
	    addrs = scm_cons (scm_list_4 (addr, netmask, broadaddr, dstaddr),
			      addrs);
	}

	if (c_iface->flags == PCAP_IF_LOOPBACK)
	    flags = scm_list_1 (spcap_if_loopback_symbol);
	else
	    flags = SCM_BOOL_F;

	iface = scm_list_4 (name, desc, scm_reverse (addrs), flags);
	allifaces = scm_cons (iface, allifaces);
    }
    pcap_freealldevs (c_allifaces);	
    return scm_reverse (allifaces);
}
#undef FUNC_NAME


SCM_DEFINE (spcap_geterr, "pcap-geterr", 1, 0, 0,
	    (SCM pcap),
	    "Returns a string detailing the last error on @var{pcap}.")
#define FUNC_NAME s_spcap_geterr
{
    pcap_t *c_pcap;

    SCM_ASSERT (SPCAP_PCAP_SMOBP (pcap), pcap, SCM_ARG1, FUNC_NAME);
    
    c_pcap = SPCAP_SMOB2PCAP (pcap);
    return scm_makfrom0str (pcap_geterr (c_pcap));
}
#undef FUNC_NAME


SCM_DEFINE (spcap_getnonblock, "pcap-getnonblock", 1, 0, 0,
	    (SCM pcap),
	    "Returns @code{#t} if @var{pcap} is in non-blocking mode,\n"
	    "@code{#f} otherwise.")
#define FUNC_NAME s_spcap_getnonblock
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *c_pcap;
    int c_val;

    SCM_ASSERT (SPCAP_PCAP_SMOBP (pcap), pcap, SCM_ARG1, FUNC_NAME);
 
    c_pcap = SPCAP_SMOB2PCAP (pcap);
    c_val = pcap_getnonblock (c_pcap, errbuf);
    if (c_val == -1)
	scm_error (spcap_error_symbol, FUNC_NAME, errbuf, SCM_EOL, SCM_EOL);
    else
	return c_val ? SCM_BOOL_T : SCM_BOOL_F;
}
#undef FUNC_NAME


SCM_DEFINE (spcap_is_swapped, "pcap-is-swapped?", 1, 0, 0,
	    (SCM pcap),
	    "Returns @code{#t} if @var{pcap} was saved on a machine\n"
	    "with different byte order to the current one, @code{#f}\n"
	    "otherwise.")
#define FUNC_NAME s_spcap_is_swapped
{
    pcap_t *c_pcap;

    SCM_ASSERT (SPCAP_PCAP_SMOBP (pcap), pcap, SCM_ARG1, FUNC_NAME);

    c_pcap = SPCAP_SMOB2PCAP (pcap);
    return pcap_is_swapped (c_pcap) ? SCM_BOOL_T : SCM_BOOL_F;
}
#undef FUNC_NAME



SCM_DEFINE (spcap_lookupdev, "pcap-lookupdev", 0, 0, 0,
	    (),
	    "Returns the name of an interface suitable for passing to\n"
	    "@code{pcap-open-live} and @code{pcap-lookupnet}.")
#define FUNC_NAME s_spcap_lookupdev
{
    char *c_name;
    char errbuf[PCAP_ERRBUF_SIZE];

    c_name = pcap_lookupdev (errbuf);
    if (c_name)
	return scm_makfrom0str (c_name);
    else
	scm_error (spcap_error_symbol, FUNC_NAME, errbuf, SCM_EOL, SCM_EOL);
}
#undef FUNC_NAME


SCM_DEFINE (spcap_lookupnet, "pcap-lookupnet", 1, 0, 0,
	    (SCM device),
	    "Returns a pair containing the network and mask associated with\n"
	    "@var{device}.")
#define FUNC_NAME s_spcap_lookupnet
{
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 c_net, c_mask;
    
    SCM_ASSERT (SCM_STRINGP (device), device, SCM_ARG1, FUNC_NAME);

    if (pcap_lookupnet (SCM_STRING_CHARS (device),
			&c_net, &c_mask, errbuf) == -1)
	scm_error (spcap_error_symbol, FUNC_NAME, errbuf, SCM_EOL, SCM_EOL);
    else
	return scm_cons (scm_ulong2num (c_net), scm_ulong2num (c_mask));
}
#undef FUNC_NAME


SCM_DEFINE (spcap_loop, "pcap-loop", 3, 0, 0,
	    (SCM pcap, SCM cnt, SCM callback),
	    "Collects packets from @var{pcap} and calls @var{callback} on each.\n"
	    "At most @var{cnt} packets will be processed, perhaps fewer.\n  If\n"
	    "@var{cnt} is @code{-1}, a bufferful (if live) or a fileful (if dead)\n"
	    "is processed en-masse. \n"
	    "@var{callback} should accept an argument like that returned by\n"
	    "@code{pcap-next}.  If @var{callback} is a pcap-dumper, the C\n"
	    "@code{pcap_dump} function will be used.\n"
	    "The number of packets processed is returned.")
#define FUNC_NAME s_spcap_loop
{
    int c_result;
    pcap_t * c_pcap;

    SCM_ASSERT (SPCAP_PCAP_SMOBP (pcap), pcap, SCM_ARG1, FUNC_NAME);
    SCM_ASSERT (SCM_INUMP (cnt), cnt, SCM_ARG2, FUNC_NAME);
    
    c_pcap = SPCAP_SMOB2PCAP (pcap);

    if (SPCAP_PCAP_DUMPER_SMOBP (callback))
	c_result = pcap_loop (c_pcap, scm_num2int (cnt, SCM_ARG2, FUNC_NAME),
			      pcap_dump,
			      (u_char *) SPCAP_SMOB2PCAP_DUMPER (callback));
    else if (scm_procedure_p (callback))
	c_result = pcap_loop (c_pcap, scm_num2int (cnt, SCM_ARG2, FUNC_NAME),
			      spcap_metacallback, (u_char *) callback);
    else
	SCM_WRONG_TYPE_ARG (SCM_ARG3, callback);

    scm_remember_upto_here_1 (pcap);

    if (c_result < 0)
	scm_error (spcap_error_symbol, FUNC_NAME,  pcap_geterr (c_pcap), SCM_EOL, SCM_EOL);
    else
	return scm_int2num (c_result);
}
#undef FUNC_NAME


SCM_DEFINE (spcap_major_version, "pcap-major-version", 1, 0, 0,
	    (SCM pcap),
	    "Returns the major number of the version of pcap used\n"
	    "to write the savefile @var{pcap}.")
#define FUNC_NAME s_spcap_major_version
{
    pcap_t *c_pcap;

    SCM_ASSERT (SPCAP_PCAP_SMOBP (pcap), pcap, SCM_ARG1, FUNC_NAME);
    
    c_pcap = SPCAP_SMOB2PCAP (pcap);
    return (SCM_MAKINUM (pcap_major_version (c_pcap)));
}
#undef FUNC_NAME


SCM_DEFINE (spcap_minor_version, "pcap-minor-version", 1, 0, 0,
	    (SCM pcap),
	    "Returns the minor number of the version of pcap used\n"
	    "to write the savefile @var{pcap}.")
#define FUNC_NAME s_spcap_minor_version
{
    pcap_t *c_pcap;

    SCM_ASSERT (SPCAP_PCAP_SMOBP (pcap), pcap, SCM_ARG1, FUNC_NAME);
    
    c_pcap = SPCAP_SMOB2PCAP (pcap);
    return (SCM_MAKINUM (pcap_minor_version (c_pcap)));
}
#undef FUNC_NAME


SCM_DEFINE (spcap_next, "pcap-next", 1, 0, 0,
	    (SCM pcap),
	    "Reads the next packet from @var{pcap}.  Returns a list\n"
	    "of four items.  The first is a pair comprising the seconds from\n"
	    "the Unix epoch, and microseconds when the packet was recorded.  The\n"
	    "snaplen and wire-length of the packet are next, and finally comes \n"
	    "an SRFI-4 u8vector of the packet data itself.")
#define FUNC_NAME s_spcap_next
{
    const u_char *pkt;
    struct pcap_pkthdr pkthdr;
    pcap_t *c_pcap;

    SCM_ASSERT (SPCAP_PCAP_SMOBP (pcap), pcap, SCM_ARG1, FUNC_NAME);
    
    c_pcap = SPCAP_SMOB2PCAP (pcap);
    pkt = pcap_next (c_pcap, &pkthdr);
    if (pkt == (u_char *) -1)
	scm_error (spcap_error_symbol, FUNC_NAME, pcap_geterr (c_pcap), SCM_EOL, SCM_EOL);
    else
	return spcap_c2scm (pkt, &pkthdr);
}
#undef FUNC_NAME


SCM_DEFINE (spcap_open_dead, "pcap-open-dead", 2, 0, 0,
	    (SCM linktype, SCM snaplen),
	    "Returns a pcap suitable for passing to @code{pcap-compile}.\n"
	    "@var{linktype} should be a symbol: see @code{pcap-datalink}.")
#define FUNC_NAME s_spcap_open_dead
{
    int c_linktype, c_snaplen;
    pcap_t *c_pcap;

    SCM_ASSERT (SCM_SYMBOLP (linktype), linktype, SCM_ARG1, FUNC_NAME);
    /* snaplen is checked below.  */

    c_linktype = scm2linktype (linktype);
    if (c_linktype == -1)
	scm_error (spcap_error_symbol, FUNC_NAME, "Unknown linktype ~S", 
		   scm_list_1 (linktype), SCM_EOL);
    
    c_snaplen = scm_num2int (snaplen, SCM_ARG2, FUNC_NAME);
    c_pcap = pcap_open_dead (c_linktype, c_snaplen);
    
    SCM_RETURN_NEWSMOB (spcap_pcap_smob_tag, c_pcap);
}
#undef FUNC_NAME


SCM_DEFINE (spcap_open_live, "pcap-open-live", 4, 0, 0,
	    (SCM devicename, SCM snaplen, SCM promiscuous, SCM timeout),
	    "Open a packet capture on network device @var{devicename}.\n"
	    "@var{snaplen} is the maximum number of octets to capture from\n"
	    "each packet.  If @var{promiscuous} is true, the network device\n"
	    "will be put in promiscuous mode.  @var{timeout} specifies a\n"
	    "number of milliseconds to wait after reading a packet before\n"
	    "returning, such that several packets may be read in one operation.\n"
	    "Returns a @code{pcap} object.")
#define FUNC_NAME s_spcap_open_live
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *c_pcap;
    int c_promiscuous, c_timeout, c_snaplen;
    
    SCM_ASSERT (SCM_STRINGP (devicename), devicename, SCM_ARG1, FUNC_NAME);
    SCM_ASSERT (SCM_BOOLP (promiscuous), promiscuous, SCM_ARG3, FUNC_NAME);

    c_snaplen = scm_num2int (snaplen, SCM_ARG2, FUNC_NAME);
    c_timeout = scm_num2int (timeout, SCM_ARG4, FUNC_NAME);
    c_promiscuous = SCM_NFALSEP (promiscuous);

    c_pcap = pcap_open_live (SCM_STRING_CHARS (devicename), c_snaplen, 
			     c_promiscuous, c_timeout, errbuf);
    if (c_pcap)
	SCM_RETURN_NEWSMOB (spcap_pcap_smob_tag, c_pcap);
    else
	scm_error (spcap_error_symbol, FUNC_NAME, errbuf, SCM_EOL, SCM_EOL);
}
#undef FUNC_NAME


SCM_DEFINE (spcap_open_offline, "pcap-open-offline", 1, 0, 0,
	    (SCM filename),
	    "Opens @var{filename} for reading.  If @code{\"-\"} is\n"
	    "specified, input is taken from stdin.  A @code{pcap} object\n"
	    "is returned.")
#define FUNC_NAME s_spcap_open_offline
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *c_pcap;

    SCM_ASSERT (SCM_STRINGP (filename), filename, SCM_ARG1, FUNC_NAME);

    c_pcap = pcap_open_offline (SCM_STRING_CHARS (filename), errbuf);
    if (c_pcap)
	SCM_RETURN_NEWSMOB (spcap_pcap_smob_tag, c_pcap);
    else
	scm_error (spcap_error_symbol, FUNC_NAME, errbuf, SCM_EOL, SCM_EOL);
}
#undef FUNC_NAME


SCM_DEFINE (spcap_perror, "pcap-perror", 1, 1, 0,
	    (SCM pcap, SCM prefix),
	    "Prints the latest error of @var{pcap} to stderr.  If @var{prefix}\n"
	    "is specified, it is printed before the error message.")
#define FUNC_NAME s_spcap_perror
{
    char *c_prefix;
    pcap_t *c_pcap;

    SCM_ASSERT (SPCAP_PCAP_SMOBP (pcap), pcap, SCM_ARG1, FUNC_NAME);

    if (SCM_UNBNDP (prefix))
	c_prefix = NULL;
    else
    {
	SCM_ASSERT (SCM_STRINGP (prefix), prefix, SCM_ARG2, FUNC_NAME);
	c_prefix = SCM_STRING_CHARS (prefix);
    }
    c_pcap = SPCAP_SMOB2PCAP (pcap);
    pcap_perror (c_pcap, c_prefix);
    return SCM_UNSPECIFIED;
}
#undef FUNC_NAME


SCM_DEFINE (spcap_setfilter, "pcap-setfilter", 2, 0, 0,
	    (SCM pcap, SCM bpf_program),
	    "Sets the filter on @var{pcap} to @var{bfp_program}.")
#define FUNC_NAME s_spcap_setfilter
{
    SCM_ASSERT (SPCAP_PCAP_SMOBP (pcap), pcap, SCM_ARG1, FUNC_NAME);
    SCM_ASSERT (SPCAP_BPF_PROGRAM_SMOBP (bpf_program), bpf_program, SCM_ARG2, FUNC_NAME);
    
    if (! pcap_setfilter (SPCAP_SMOB2PCAP (pcap),
			  SPCAP_SMOB2BPF_PROGRAM (bpf_program)))
	return SCM_UNSPECIFIED;
    else
	scm_error (spcap_error_symbol, FUNC_NAME, 
		   pcap_geterr (SPCAP_SMOB2PCAP (pcap)),
		   SCM_EOL, SCM_EOL);
}
#undef FUNC_NAME


SCM_DEFINE (spcap_setnonblock, "pcap-setnonblock", 2, 0, 0,
	    (SCM pcap, SCM block),
	    "Places @var{pcap} into non-blocking mode if @var{block}\n"
	    "is true, and vice-versa.")
#define FUNC_NAME s_spcap_setnonblock
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *c_pcap;
    int c_block;

    SCM_ASSERT (SPCAP_PCAP_SMOBP (pcap), pcap, SCM_ARG1, FUNC_NAME);
    SCM_ASSERT (SCM_BOOLP (block), block, SCM_ARG2, FUNC_NAME);

    c_pcap = SPCAP_SMOB2PCAP (pcap);
    c_block = SCM_NFALSEP (block);
    if (pcap_setnonblock (c_pcap, c_block, errbuf))
	scm_error (spcap_error_symbol, FUNC_NAME, errbuf, SCM_EOL, SCM_EOL);
    else
	return SCM_UNSPECIFIED;
}
#undef FUNC_NAME


SCM_DEFINE (spcap_snapshot, "pcap-snapshot", 1, 0, 0,
	    (SCM pcap),
	    "Returns the snapshot length specified when\n"
	    "@var{pcap} was opened.")
#define FUNC_NAME s_spcap_snapshot
{
    SCM_ASSERT (SPCAP_PCAP_SMOBP (pcap), pcap, SCM_ARG1, FUNC_NAME);

    return SCM_MAKINUM (pcap_snapshot SPCAP_SMOB2PCAP (pcap));
}
#undef FUNC_NAME


SCM_DEFINE (spcap_stats, "pcap-stats", 1, 0, 0,
	    (SCM pcap),
	    "Returns a list of packets received, packets dropped,\n"
	    "and packets dropped by the interface for @var{pcap}.")
#define FUNC_NAME s_spcap_stats
{
    pcap_t *c_pcap;
    int v;
    struct pcap_stat c_stats;

    SCM_ASSERT (SPCAP_PCAP_SMOBP (pcap), pcap, SCM_ARG1, FUNC_NAME);

    c_pcap = SPCAP_SMOB2PCAP (pcap);
    v = pcap_stats (c_pcap, &c_stats);
    if (v == 0)
	return scm_list_3 (scm_uint2num (c_stats.ps_recv),
			   scm_uint2num (c_stats.ps_drop),
			   scm_uint2num (c_stats.ps_ifdrop));
    else 
	scm_error (spcap_error_symbol, FUNC_NAME, pcap_geterr (c_pcap), SCM_EOL, SCM_EOL);
}
#undef FUNC_NAME


SCM_DEFINE (spcap_strerror, "pcap-strerror", 1, 0, 0,
	    (SCM errno),
	    "Returns a string explaining error code @var{errno}.")
#define FUNC_NAME s_spcap_strerror
{
    char *c_string;

    SCM_ASSERT (SCM_INUMP (errno), errno, SCM_ARG1, FUNC_NAME);
    
    c_string = pcap_strerror (scm_num2int (errno, SCM_ARG1, FUNC_NAME));
    return scm_makfrom0str (c_string);
}
#undef FUNC_NAME


/* The next three functions are not in the libpcap library, but
   omitting them would be in bad taste. */

SCM_DEFINE (spcap_bpf_program_p, "pcap-bpf-program?", 1, 0, 0,
	    (SCM obj),
	    "Returns @code{#t} if @var{obj} is a BPF program, @code{#f}\n"
	    "otherwise.")
#define FUNC_NAME s_spcap_bpf_program_p
{
    return SPCAP_BPF_PROGRAM_SMOBP (obj) ? SCM_BOOL_T : SCM_BOOL_F;
}
#undef FUNC_NAME


SCM_DEFINE (spcap_pcap_p, "pcap-pcap?", 1, 0, 0,
	    (SCM obj),
	    "Returns @code{#t} if @var{obj} is a PCAP object, @code{#f}\n"
	    "otherwise.")
#define FUNC_NAME s_spcap_pcap_p
{
    return SPCAP_PCAP_SMOBP (obj) ? SCM_BOOL_T : SCM_BOOL_F;
}
#undef FUNC_NAME


SCM_DEFINE (spcap_dumper_p, "pcap-dumper?", 1, 0, 0,
	    (SCM obj),
	    "Returns @code{#t} if @var{obj} is a PCAP dumper, @code{#f}\n"
	    "otherwise.")
#define FUNC_NAME s_spcap_dumper_p
{
    return SPCAP_PCAP_DUMPER_SMOBP (obj) ? SCM_BOOL_T : SCM_BOOL_F;
}
#undef FUNC_NAME


extern void
spcap_extension_init ()
{
    int i;
    SCM symbol;

    spcap_pcap_smob_tag = scm_make_smob_type ("pcap", 0);
    scm_set_smob_mark (spcap_pcap_smob_tag, NULL);
    scm_set_smob_free (spcap_pcap_smob_tag, spcap_pcap_smob_free);
    scm_set_smob_print (spcap_pcap_smob_tag, spcap_pcap_smob_print);
    scm_set_smob_equalp (spcap_pcap_smob_tag, NULL);

    spcap_pcap_dumper_smob_tag = scm_make_smob_type ("pcap-dumper", 0);
    scm_set_smob_mark (spcap_pcap_dumper_smob_tag, NULL);
    scm_set_smob_free (spcap_pcap_dumper_smob_tag, spcap_pcap_dumper_smob_free);
    scm_set_smob_print (spcap_pcap_dumper_smob_tag, spcap_pcap_dumper_smob_print);
    scm_set_smob_equalp (spcap_pcap_dumper_smob_tag, NULL);

    spcap_bpf_program_smob_tag = scm_make_smob_type ("bpf-program", 0);
    scm_set_smob_mark (spcap_bpf_program_smob_tag, NULL);
    scm_set_smob_free (spcap_bpf_program_smob_tag, spcap_bpf_program_smob_free);
    scm_set_smob_print (spcap_bpf_program_smob_tag, spcap_bpf_program_smob_print);
    scm_set_smob_equalp (spcap_bpf_program_smob_tag, NULL);

    spcap_error_symbol = scm_str2symbol ("pcap-error");
    scm_gc_protect_object (spcap_error_symbol);
    spcap_if_loopback_symbol = scm_str2symbol ("PCAP_IF_LOOPBACK");
    scm_gc_protect_object (spcap_if_loopback_symbol);
    
    /* Create symbols for the datalink types.  */
    for (i=0; i<(sizeof (linktype_table) / sizeof (struct lookup)); i++)
    {
	/* We need to use a local variable for this, to make sure the
	   symbol doesn't get GC'd before it gets protected. */
	symbol = scm_str2symbol (linktype_table[i].name);
	linktype_table[i].symbol = symbol;
	scm_gc_protect_object (symbol);
    }

#include "guile-pcap.x"
}


/* Put the components of a sockaddr into a new SCM vector. 

   XXX Snarfed from guile-1.6.1/libguile/socket.c.  Ask the guile
   maintainers if this can be exported...  */
static SCM
scm_addr_vector (const struct sockaddr *address, const char *proc)
{
  short int fam = address->sa_family;
  SCM result;
  SCM *ve;

  switch (fam)
    {
    case AF_INET:
      {
	const struct sockaddr_in *nad = (struct sockaddr_in *) address;

	result = scm_c_make_vector (3, SCM_UNSPECIFIED);
	ve = SCM_VELTS (result);
	ve[0] = scm_ulong2num ((unsigned long) fam);
	ve[1] = scm_ulong2num (ntohl (nad->sin_addr.s_addr));
	ve[2] = scm_ulong2num ((unsigned long) ntohs (nad->sin_port));
      }
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      {
	const struct sockaddr_in6 *nad = (struct sockaddr_in6 *) address;

	result = scm_c_make_vector (5, SCM_UNSPECIFIED);
	ve = SCM_VELTS (result);
	ve[0] = scm_ulong2num ((unsigned long) fam);
	ve[1] = ipv6_net_to_num (nad->sin6_addr.s6_addr);
	ve[2] = scm_ulong2num ((unsigned long) ntohs (nad->sin6_port));
	ve[3] = scm_ulong2num ((unsigned long) nad->sin6_flowinfo);
#ifdef HAVE_SIN6_SCOPE_ID
	ve[4] = scm_ulong2num ((unsigned long) nad->sin6_scope_id);
#else
	ve[4] = SCM_INUM0;
#endif
      }
      break;
#endif
#ifdef HAVE_UNIX_DOMAIN_SOCKETS
    case AF_UNIX:
      {
	const struct sockaddr_un *nad = (struct sockaddr_un *) address;

	result = scm_c_make_vector (2, SCM_UNSPECIFIED);
	ve = SCM_VELTS (result);
	ve[0] = scm_ulong2num ((unsigned long) fam);
	ve[1] = scm_mem2string (nad->sun_path, strlen (nad->sun_path));
      }
      break;
#endif
    default:
      scm_misc_error (proc, "Unrecognised address family: ~A",
		      scm_list_1 (SCM_MAKINUM (fam)));
    }
  return result;
}


/* XXX This is very naughty, since we rely on the internal composition
   of the SRFI-4 vectors.  Still, it's fast. */
static SCM
make_u8_vector (const unsigned char *data, int size)
{
    SCM v;

    v = scm_make_u8vector (SCM_MAKINUM (size), SCM_UNDEFINED);
    memcpy ((void *) SCM_CELL_WORD_3 (v), data, size);
    return v;
}
