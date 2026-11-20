/*
 * This file is part of JSTUN.
 *
 * Copyright (c) 2005 Thomas King <king@t-king.de> - All rights
 * reserved.
 *
 * This software is licensed under either the GNU Public License (GPL),
 * or the Apache 2.0 license. Copies of both license agreements are
 * included in this distribution.
 */

package de.javawi.jstun.util;

import java.text.Normalizer;

/**
 * RFC 4013 SASLprep string preparation profile for STUN/TURN user names,
 * realms, and passwords (RFC 5389 §10.1.3, §15.4 and RFC 5769 §2.4).
 * <p>
 * Applies RFC 4013 mapping (Table B.1 mapped to nothing; Table C.1.2 non-ASCII
 * spaces mapped to ASCII space {@code U+0020}), Unicode NFKC normalization,
 * prohibited output checks (Tables C.1.2, C.2.1, C.2.2, C.3–C.9), and RFC 3454
 * §6 bidirectional checks.
 */
public final class SaslPrep {

	private SaslPrep() {
	}

	/**
	 * Prepares the given string according to RFC 4013 (SASLprep).
	 *
	 * @param input the raw UTF-16 Java string to prepare
	 * @return the SASLprep-normalized string
	 * @throws UtilityException if {@code input} is {@code null} or contains
	 *                          prohibited characters or invalid bidirectional sequences
	 */
	public static String prepare(String input) throws UtilityException {
		if (input == null) {
			throw new UtilityException("SASLprep input must not be null");
		}
		if (input.isEmpty()) {
			return "";
		}

		// Step 1: Mapping (RFC 4013 §2.1)
		StringBuilder mapped = new StringBuilder(input.length());
		for (int i = 0; i < input.length();) {
			int cp = input.codePointAt(i);
			i += Character.charCount(cp);
			if (isMappedToNothing(cp)) {
				continue;
			}
			if (isNonAsciiSpace(cp)) {
				mapped.append(' ');
			} else {
				mapped.appendCodePoint(cp);
			}
		}

		// Step 2: Normalization (RFC 4013 §2.2) — Unicode NFKC
		String normalized = Normalizer.normalize(mapped.toString(), Normalizer.Form.NFKC);

		// Step 3 & 4: Prohibited output (§2.3) and Bidirectional checks (§2.4 / RFC 3454 §6)
		boolean hasRandAL = false;
		boolean hasL = false;
		boolean firstIsRandAL = false;
		boolean lastIsRandAL = false;
		boolean first = true;

		for (int i = 0; i < normalized.length();) {
			int cp = normalized.codePointAt(i);
			i += Character.charCount(cp);

			if (isProhibited(cp)) {
				throw new UtilityException(
						"SASLprep prohibited code point: U+" + String.format("%04X", cp));
			}

			byte dir = Character.getDirectionality(cp);
			boolean isRandAL = (dir == Character.DIRECTIONALITY_RIGHT_TO_LEFT
					|| dir == Character.DIRECTIONALITY_RIGHT_TO_LEFT_ARABIC);
			boolean isL = (dir == Character.DIRECTIONALITY_LEFT_TO_RIGHT);

			if (first) {
				firstIsRandAL = isRandAL;
				first = false;
			}
			lastIsRandAL = isRandAL;
			if (isRandAL) {
				hasRandAL = true;
			}
			if (isL) {
				hasL = true;
			}
		}

		if (hasRandAL) {
			if (hasL) {
				throw new UtilityException(
						"SASLprep bidirectional violation: mixes RandALCat and LCat characters");
			}
			if (!firstIsRandAL || !lastIsRandAL) {
				throw new UtilityException(
						"SASLprep bidirectional violation: RandALCat must be first and last character");
			}
		}

		return normalized;
	}

	private static boolean isMappedToNothing(int cp) {
		return cp == 0x00AD
				|| cp == 0x034F
				|| cp == 0x1806
				|| (cp >= 0x180B && cp <= 0x180D)
				|| (cp >= 0x200B && cp <= 0x200D)
				|| cp == 0x2060
				|| (cp >= 0xFE00 && cp <= 0xFE0F)
				|| cp == 0xFEFF;
	}

	private static boolean isNonAsciiSpace(int cp) {
		return cp == 0x00A0
				|| cp == 0x1680
				|| (cp >= 0x2000 && cp <= 0x200B)
				|| cp == 0x202F
				|| cp == 0x205F
				|| cp == 0x3000;
	}

	private static boolean isProhibited(int cp) {
		// C.1.2 Non-ASCII spaces
		if (isNonAsciiSpace(cp)) {
			return true;
		}
		// C.2.1 ASCII control characters
		if (cp <= 0x001F || cp == 0x007F) {
			return true;
		}
		// C.2.2 Non-ASCII control characters
		if ((cp >= 0x0080 && cp <= 0x009F)
				|| cp == 0x06DD || cp == 0x070F || cp == 0x180E
				|| cp == 0x200C || cp == 0x200D
				|| cp == 0x2028 || cp == 0x2029
				|| (cp >= 0x2060 && cp <= 0x2063)
				|| (cp >= 0x206A && cp <= 0x206F)
				|| cp == 0xFEFF
				|| (cp >= 0xFFF9 && cp <= 0xFFFC)
				|| (cp >= 0x1D173 && cp <= 0x1D17A)) {
			return true;
		}
		// C.3 Private use
		if ((cp >= 0xE000 && cp <= 0xF8FF)
				|| (cp >= 0xF0000 && cp <= 0xFFFFD)
				|| (cp >= 0x100000 && cp <= 0x10FFFD)) {
			return true;
		}
		// C.4 Non-character code points
		if ((cp >= 0xFDD0 && cp <= 0xFDEF)
				|| (cp & 0xFFFF) == 0xFFFE
				|| (cp & 0xFFFF) == 0xFFFF) {
			return true;
		}
		// C.5 Surrogate code points
		if (cp >= 0xD800 && cp <= 0xDFFF) {
			return true;
		}
		// C.6 Inappropriate for plain text
		if (cp >= 0xFFF9 && cp <= 0xFFFD) {
			return true;
		}
		// C.7 Inappropriate for canonical representation
		if (cp >= 0x2FF0 && cp <= 0x2FFB) {
			return true;
		}
		// C.8 Change display properties / deprecated
		if (cp == 0x0340 || cp == 0x0341
				|| cp == 0x200E || cp == 0x200F
				|| (cp >= 0x202A && cp <= 0x202E)) {
			return true;
		}
		// C.9 Tagging characters
		return cp == 0xE0001 || (cp >= 0xE0020 && cp <= 0xE007F);
	}
}
