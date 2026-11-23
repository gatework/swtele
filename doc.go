// Package swtele is the vendor-neutral runtime model of a network device:
// the ledger entry a decoder assembles from command outputs and
// configuration, and that analyses (topology, endpoint location, optics,
// counters, health) read.
//
// A Device is an aggregate of components — System, Stack, Interfaces,
// Aggregates, Bridging, Routing, Neighbors — each owning its own facts.
// Values that a device may not report are Opt, so "zero" and "not
// reported" stay distinct. Units are normalized: power in dBm, temperature
// in °C, rates in bit/s, memory in bytes, times in UTC.
//
// The package does no I/O.
package swtele
