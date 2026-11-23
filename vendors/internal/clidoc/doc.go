// Package clidoc prepares one command output for a vendor decoder: it
// strips the command echo and closing prompt, recognizes CLI rejections in
// the body, tracks which lines a decoder consumed, and parses the values
// device CLIs print (counts with "--" and "Overflow", speeds, durations,
// timestamps).
//
// Decoders mark every line they understand; Finish reports the rest as
// netops parse "unparsed_line" issues, so a format drift degrades a
// dimension to partial instead of silently losing facts.
package clidoc
