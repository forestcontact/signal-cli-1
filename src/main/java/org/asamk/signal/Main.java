/*
  Copyright (C) 2015-2021 AsamK and contributors

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.asamk.signal;

import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.impl.Arguments;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import net.sourceforge.argparse4j.inf.Namespace;

import org.asamk.signal.commands.exceptions.CommandException;
import org.asamk.signal.commands.exceptions.IOErrorException;
import org.asamk.signal.commands.exceptions.UnexpectedErrorException;
import org.asamk.signal.commands.exceptions.UntrustedKeyErrorException;
import org.asamk.signal.commands.exceptions.UserErrorException;
import org.asamk.signal.manager.LibSignalLogger;
import org.asamk.signal.manager.config.IasTrustStore;
import org.asamk.signal.util.SecurityProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.whispersystems.signalservice.api.push.TrustStore;

import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Enumeration;

public class Main {

    public static void main(String[] args) {
        // enable unlimited strength crypto via Policy, supported on relevant JREs
        Security.setProperty("crypto.policy", "unlimited");
        installSecurityProviderWorkaround();

        // Configuring the logger needs to happen before any logger is initialized
        final var isVerbose = isVerbose(args);
        configureLogging(isVerbose);

        var parser = App.buildArgumentParser();

        var ns = parser.parseArgsOrFail(args);
/*
        //Ugly hax for Auxin development DO NOT COMMIT
        try {
            TrustStore contactTrustStore = new IasTrustStore();

            var keyStore = KeyStore.getInstance("BKS");
            keyStore.load(contactTrustStore.getKeyStoreInputStream(),
                    contactTrustStore.getKeyStorePassword().toCharArray());
            Enumeration<String> aliases = keyStore.aliases();
            String password = new String("whisper");
            KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(password.toCharArray());
            while(aliases.hasMoreElements() ) {
                String next = aliases.nextElement();
                if( keyStore.isKeyEntry(next) ) {
                    System.out.println("Key:");
                    KeyStore.Entry entry = keyStore.getEntry(next, protection);
                    for(KeyStore.Entry.Attribute attribute: entry.getAttributes() ) {
                        System.out.println(attribute.getName());
                        System.out.println(attribute.getValue());
                    }
                }
                else if ( keyStore.isCertificateEntry(next) ){
                    System.out.println("Cert:");
                    X509Certificate cert = (X509Certificate) keyStore.getCertificate(next);
                    System.out.println(cert.getPublicKey());
                    //System.out.println(cert.getEncoded());

                    FileWriter fout = new FileWriter("/home/gyro/out.pem");
                    PemWriter pwrite = new PemWriter(fout);
                    pwrite.writeObject(new PemObject("CERTIFICATE", cert.getEncoded()));
                    pwrite.flush();;
                    fout.flush();
                }
            }
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            throw new AssertionError(e);
        }
*/
        int status = 0;
        try {
            new App(ns).init();
        } catch (CommandException e) {
            System.err.println(e.getMessage());
            if (isVerbose && e.getCause() != null) {
                e.getCause().printStackTrace();
            }
            status = getStatusForError(e);
        } catch (Throwable e) {
            e.printStackTrace();
            status = 2;
        }
        System.exit(status);
    }

    private static void installSecurityProviderWorkaround() {
        // Register our own security provider
        Security.insertProviderAt(new SecurityProvider(), 1);
        Security.addProvider(new BouncyCastleProvider());
    }

    private static boolean isVerbose(String[] args) {
        var parser = ArgumentParsers.newFor("signal-cli").build().defaultHelp(false);
        parser.addArgument("--verbose").action(Arguments.storeTrue());

        Namespace ns;
        try {
            ns = parser.parseKnownArgs(args, null);
        } catch (ArgumentParserException e) {
            return false;
        }

        return Boolean.TRUE.equals(ns.getBoolean("verbose"));
    }

    private static void configureLogging(final boolean verbose) {
        if (verbose) {
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "debug");
            System.setProperty("org.slf4j.simpleLogger.showThreadName", "true");
            System.setProperty("org.slf4j.simpleLogger.showShortLogName", "false");
            System.setProperty("org.slf4j.simpleLogger.showDateTime", "true");
            System.setProperty("org.slf4j.simpleLogger.dateTimeFormat", "yyyy-MM-dd'T'HH:mm:ss.SSSXX");
            LibSignalLogger.initLogger();
        } else {
            System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "info");
            System.setProperty("org.slf4j.simpleLogger.showThreadName", "false");
            System.setProperty("org.slf4j.simpleLogger.showShortLogName", "true");
            System.setProperty("org.slf4j.simpleLogger.showDateTime", "false");
        }
    }

    private static int getStatusForError(final CommandException e) {
        if (e instanceof UserErrorException) {
            return 1;
        } else if (e instanceof UnexpectedErrorException) {
            return 2;
        } else if (e instanceof IOErrorException) {
            return 3;
        } else if (e instanceof UntrustedKeyErrorException) {
            return 4;
        } else {
            return 2;
        }
    }
}
