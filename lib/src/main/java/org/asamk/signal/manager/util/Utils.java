package org.asamk.signal.manager.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.fingerprint.Fingerprint;
import org.whispersystems.libsignal.fingerprint.NumericFingerprintGenerator;
import org.whispersystems.signalservice.api.push.SignalServiceAddress;
import org.whispersystems.signalservice.api.util.StreamDetails;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLConnection;
import java.nio.file.Files;
import java.util.Locale;

public class Utils {

    private final static Logger logger = LoggerFactory.getLogger(Utils.class);

    public static String getFileMimeType(File file, String defaultMimeType) throws IOException {
        var mime = Files.probeContentType(file.toPath());
        if (mime == null) {
            try (InputStream bufferedStream = new BufferedInputStream(new FileInputStream(file))) {
                mime = URLConnection.guessContentTypeFromStream(bufferedStream);
            }
        }
        if (mime == null) {
            return defaultMimeType;
        }
        return mime;
    }

    public static StreamDetails createStreamDetailsFromFile(File file) throws IOException {
        InputStream stream = new FileInputStream(file);
        final var size = file.length();
        final var mime = getFileMimeType(file, "application/octet-stream");
        return new StreamDetails(stream, mime, size);
    }

    public static Fingerprint computeSafetyNumber(
            boolean isUuidCapable,
            SignalServiceAddress ownAddress,
            IdentityKey ownIdentityKey,
            SignalServiceAddress theirAddress,
            IdentityKey theirIdentityKey
    ) {
        int version;
        byte[] ownId;
        byte[] theirId;

        if (isUuidCapable) {
            // Version 2: UUID user
            version = 2;
            ownId = ownAddress.getAci().toByteArray();
            theirId = theirAddress.getAci().toByteArray();
        } else {
            // Version 1: E164 user
            version = 1;
            if (!ownAddress.getNumber().isPresent() || !theirAddress.getNumber().isPresent()) {
                return null;
            }
            ownId = ownAddress.getNumber().get().getBytes();
            theirId = theirAddress.getNumber().get().getBytes();
        }

        return new NumericFingerprintGenerator(5200).createFor(version,
                ownId,
                ownIdentityKey,
                theirId,
                theirIdentityKey);
    }

    public static Locale getDefaultLocale() {
        final var locale = Locale.getDefault();
        if (locale == null) {
            return null;
        }
        try {
            Locale.LanguageRange.parse(locale.getLanguage() + "-" + locale.getCountry());
        } catch (IllegalArgumentException e) {
            logger.debug("Invalid locale, ignoring: {}", locale);
            return null;
        }

        return locale;
    }
}
