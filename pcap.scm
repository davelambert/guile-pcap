;;;; Copyright (C) 2003 David J. Lambert
;;;; 
;;;; This program is free software; you can redistribute it and/or modify
;;;; it under the terms of the GNU General Public License as published by
;;;; the Free Software Foundation; either version 2, or (at your option)
;;;; any later version.
;;;; 
;;;; This program is distributed in the hope that it will be useful,
;;;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;;;; GNU General Public License for more details.
;;;; 
;;;; You should have received a copy of the GNU General Public License
;;;; along with this software; see the file COPYING.  If not, write to
;;;; the Free Software Foundation, Inc., 59 Temple Place, Suite 330,
;;;; Boston, MA 02111-1307 USA
;;;; 

(define-module (net pcap)
  #:use-module (ice-9 documentation)
  #:use-module (srfi srfi-4))

(load-extension "libguile-pcap" "spcap_extension_init")

(set! documentation-files (cons (%search-load-path "net/pcap.txt")
				documentation-files))

(export pcap-compile
	pcap-datalink
	pcap-dispatch
	pcap-dump
	pcap-dump-open
	pcap-fileno
	pcap-findalldevs
	pcap-geterr
	pcap-getnonblock
	pcap-is-swapped?
	pcap-lookupdev
	pcap-lookupnet
	pcap-loop
	pcap-major-version
	pcap-minor-version
	pcap-next
	pcap-open-dead
	pcap-open-live
	pcap-open-offline
	pcap-perror
	pcap-setfilter
	pcap-setnonblock
	pcap-snapshot
	pcap-stats
	pcap-strerror

	;; These are not part of the C libpcap interface.
	pcap-pcap?
	pcap-dumper?
	pcap-bpf-program?)
