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

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Provides the JSTUN version and the RFC 5389 / RFC 8489 compliant
 * SOFTWARE attribute description used to identify JSTUN on the wire.
 * <p>
 * The version is injected from the Maven {@code project.version} at build time
 * via the filtered resource {@code de/javawi/jstun/jstun.properties}.
 */
public final class JstunVersion {

	private static final String PROPERTIES_RESOURCE = "/de/javawi/jstun/jstun.properties";
	private static final String UNKNOWN = "unknown";

	/** The JSTUN version, e.g. {@code 1.0.1}. */
	public static final String VERSION = loadVersion();

	/**
	 * Textual description for the STUN SOFTWARE attribute (RFC 5389 §15.10 /
	 * RFC 8489 §14.14): includes the manufacturer/project and version number,
	 * e.g. {@code JSTUN/1.0.1 (https://github.com/tking/JSTUN)}.
	 */
	public static final String SOFTWARE = "JSTUN/" + VERSION + " (https://github.com/tking/JSTUN)";

	private JstunVersion() {
	}

	private static String loadVersion() {
		try (InputStream in = JstunVersion.class.getResourceAsStream(PROPERTIES_RESOURCE)) {
			if (in != null) {
				Properties props = new Properties();
				props.load(in);
				String version = props.getProperty("jstun.version");
				if (version != null && !version.isEmpty() && !version.startsWith("${")) {
					return version.trim();
				}
			}
		} catch (IOException e) {
			// fall through to manifest / unknown
		}
		Package pkg = JstunVersion.class.getPackage();
		if (pkg != null && pkg.getImplementationVersion() != null) {
			return pkg.getImplementationVersion();
		}
		return UNKNOWN;
	}
}
