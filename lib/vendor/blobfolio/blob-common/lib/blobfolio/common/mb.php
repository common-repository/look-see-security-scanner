<?php
 namespace blobfolio\wp\looksee\vendor\common; class mb { public static function parse_url($url, int $component = -1) { ref\cast::string($url, true); ref\mb::trim($url); $url = \preg_replace('/^:?\/\//', 'https://', $url); if (\filter_var($url, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6)) { $url = "[$url]"; } $encoded = \preg_replace_callback( '%([a-zA-Z][a-zA-Z0-9+\-.]*)?(:?//)?([^:/@?&=#\[\]]+)%usD', function ($matches) { $matches[3] = \urldecode($matches[3]); return $matches[1] . $matches[2] . $matches[3]; }, $url ); if (\PHP_URL_SCHEME !== $component) { $test = \parse_url($encoded, \PHP_URL_SCHEME); if (! $test) { $encoded = "blobfolio://$encoded"; } } $parts = \parse_url($encoded, $component); if (\is_string($parts) && \PHP_URL_SCHEME !== $component) { $parts = \str_replace(' ', '+', \urldecode($parts)); if (\PHP_URL_HOST === $component) { if (\function_exists('idn_to_ascii')) { $parts = \explode('.', $parts); ref\file::idn_to_ascii($parts); $parts = \implode('.', $parts); } ref\mb::strtolower($parts, false); $parts = \ltrim($parts, '.'); $parts = \rtrim($parts, '.'); if (0 === \strpos($parts, '[')) { $parts = \str_replace(array('[', ']'), '', $parts); ref\sanitize::ip($parts, true); $parts = "[{$parts}]"; } } } elseif (\is_array($parts)) { foreach ($parts as $k=>$v) { if (! \is_string($v)) { continue; } if ('scheme' !== $k) { $parts[$k] = \str_replace(' ', '+', \urldecode($v)); } elseif ('blobfolio' === $v) { unset($parts[$k]); continue; } if ('host' === $k) { if (\function_exists('idn_to_ascii')) { $parts[$k] = \explode('.', $parts[$k]); ref\file::idn_to_ascii($parts[$k]); $parts[$k] = \implode('.', $parts[$k]); } ref\mb::strtolower($parts[$k], false); $parts[$k] = \ltrim($parts[$k], '.'); $parts[$k] = \rtrim($parts[$k], '.'); if (0 === \strpos($parts[$k], '[')) { $parts[$k] = \str_replace(array('[', ']'), '', $parts[$k]); ref\sanitize::ip($parts[$k], true); $parts[$k] = "[{$parts[$k]}]"; } } } } return $parts; } public static function parse_str($str, &$result) { if (\function_exists('mb_parse_str')) { return \mb_parse_str($str, $result); } else { return \parse_str($str, $result); } } public static function str_pad($str, int $pad_length, $pad_string=' ', int $pad_type=\STR_PAD_RIGHT) { ref\mb::str_pad($str, $pad_length, $pad_string, $pad_type); return $str; } public static function str_split($str, int $split_length=1) { ref\mb::str_split($str, $split_length); return $str; } public static function strlen(string $str) { if (\function_exists('mb_strlen')) { return (int) \mb_strlen($str, 'UTF-8'); } return \strlen($str); } public static function strpos(string $haystack, string $needle, int $offset=0) { if (\function_exists('mb_strpos')) { return \mb_strpos($haystack, $needle, $offset, 'UTF-8'); } return \strpos($haystack, $needle, $offset); } public static function strrev($str) { ref\mb::strrev($str); return $str; } public static function strrpos(string $haystack, string $needle, int $offset=0) { if (\function_exists('mb_strrpos')) { return \mb_strrpos($haystack, $needle, $offset, 'UTF-8'); } else { return \strrpos($haystack, $needle, $offset); } } public static function strtolower($str, bool $strict=false) { ref\mb::strtolower($str, $strict); return $str; } public static function strtoupper($str, bool $strict=false) { ref\mb::strtoupper($str, $strict); return $str; } public static function substr(string $str, int $start=0, $length=null) { if (\function_exists('mb_substr')) { return \mb_substr($str, $start, $length, 'UTF-8'); } return \substr($str, $start, $length); } public static function substr_count(string $haystack, string $needle) { if (\function_exists('mb_substr_count')) { return \mb_substr_count($haystack, $needle, 'UTF-8'); } else { return \substr_count($haystack, $needle); } } public static function trim($str) { ref\mb::trim($str); return $str; } public static function ucfirst($str, bool $strict=false) { ref\mb::ucfirst($str, $strict); return $str; } public static function ucwords($str, bool $strict=false) { ref\mb::ucwords($str, $strict); return $str; } public static function wordwrap($str, int $width=75, $break="\n", bool $cut=false) { ref\mb::wordwrap($str, $width, $break, $cut); return $str; } } 