/*
 * Java Record Router CFE-35
 * Copyright (C) 2021-2024 Suomen Kanuuna Oy
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 *
 * Additional permission under GNU Affero General Public License version 3
 * section 7
 *
 * If you modify this Program, or any covered work, by linking or combining it
 * with other code, such other code is not for that reason alone subject to any
 * of the requirements of the GNU Affero GPL version 3 as long as this Program
 * is the same Program as licensed from Suomen Kanuuna Oy without any additional
 * modifications.
 *
 * Supplemented terms under GNU Affero General Public License version 3
 * section 7
 *
 * Origin of the software must be attributed to Suomen Kanuuna Oy. Any modified
 * versions must be marked as "Modified version of" The Program.
 *
 * Names of the licensors and authors may not be used for publicity purposes.
 *
 * No rights are granted for use of trade names, trademarks, or service marks
 * which are in The Program if any.
 *
 * Licensee must indemnify licensors and authors for any liability that these
 * contractual assumptions impose on licensors and authors.
 *
 * To the extent this program is licensed as part of the Commercial versions of
 * Teragrep, the applicable Commercial License may apply to this file if you as
 * a licensee so wish it.
 */
package com.teragrep.cfe_35.router;

import com.teragrep.cfe_35.config.RoutingConfig;
import com.teragrep.cfe_35.router.targets.DeadLetter;
import com.teragrep.cfe_35.router.targets.Inspection;
import com.teragrep.rlo_06.RFC5424Frame;
import com.teragrep.rlo_06.SDVector;
import com.teragrep.rlo_11.key.AppName;
import com.teragrep.rlo_11.key.Hostname;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.NoSuchElementException;
import java.util.Set;

public class CFE16RecordFrame implements Validateable, Routeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(CFE16RecordFrame.class);

    final SDVector authTokenVector;

    final RoutingLookup routingLookup;

    final RFC5424Frame rfc5424Frame;
    final int truncationLength;

    final DeadLetter deadLetter;
    final Inspection inspection;

    CFE16RecordFrame(
            RoutingLookup routingLookup,
            RFC5424Frame rfc5424Frame,
            RoutingConfig routingConfig,
            DeadLetter deadLetter,
            Inspection inspection
    ) {
        this.authTokenVector = new SDVector("CFE-16-metadata@48577", "authentication_token");
        this.routingLookup = routingLookup;
        this.rfc5424Frame = rfc5424Frame;
        this.truncationLength = routingConfig.getCfe16TruncationLength();
        this.deadLetter = deadLetter;
        this.inspection = inspection;
    }

    @Override
    public RoutingData route(byte[] data) {
        // default to dead-letter
        RoutingData routingData = new RoutingData(data, deadLetter.asSingletonSet());
        boolean routed = false;

        String cfe16Token = rfc5424Frame.structuredData.getValue(authTokenVector).toString();
        LOGGER.debug("cfe_16 routing with authToken <[{}]>", cfe16Token);

        Hostname hostname = routingLookup.getHostnameForToken(cfe16Token);
        AppName appName = routingLookup.getAppNameForToken(cfe16Token);

        if (hostname.isStub) {
            // no mapping -> dead-letter
            routingData = new RoutingData(data, deadLetter.asSingletonSet());
            LOGGER
                    .debug(
                            "routed hostname <[{}]> appName <[{}]> to <{}> due to hostname not routed. authToken <[{}]>",
                            hostname.hostname, appName.appName, deadLetter.asSingletonSet(), cfe16Token
                    );
            routed = true;
        }
        else if (!hostname.validate()) {
            // invalid -> inspection
            routingData = new RoutingData(data, inspection.asSingletonSet());
            LOGGER
                    .debug(
                            "routed hostname <[{}]> appName <[{}]> to <{}> due to hostname not valid. authToken <[{}]>",
                            hostname.hostname, appName.appName, inspection.asSingletonSet(), cfe16Token
                    );
            routed = true;
        }

        if (!routed) {
            if (appName.isStub) {
                // no mapping -> dead-letter
                routingData = new RoutingData(data, deadLetter.asSingletonSet());
                LOGGER
                        .debug(
                                "routed hostname <[{}]> appName <[{}]> to <{}> due to appName not routed. authToken <[{}]>",
                                hostname.hostname, appName.appName, deadLetter.asSingletonSet(), cfe16Token
                        );
                routed = true;

            }
            else if (!appName.validate()) {
                // replace appName with "" to be compatible with cfe-07
                AppName forcedAppName = new AppName("");
                LOGGER
                        .debug(
                                "changed hostname <[{}]> appName <[{}]> to forcedAppName <{}> due to appName not valid. authToken <[{}]>",
                                hostname.hostname, appName.appName, forcedAppName.appName, cfe16Token
                        );
                appName = forcedAppName;
            }
        }

        if (!routed) {
            if (!appName.equals(appName.asCompatible())) {
                // appName changed, log about it
                AppName compatibleAppName = appName.asCompatible();
                LOGGER
                        .info(
                                "changed appName from <[{}]> to compatibleAppName <[{}]>. authToken <[{}]>", appName,
                                compatibleAppName, cfe16Token
                        );
                appName = compatibleAppName;
            }

            // replace hostname, appName
            byte[] modifiedData = ReplacementUtilityClass.replace(rfc5424Frame, hostname.hostname, appName.appName);

            // truncate if necessary
            byte[] truncatedData = TruncationUtilityClass.truncate(modifiedData, truncationLength);
            if (truncatedData.length != modifiedData.length) {
                LOGGER
                        .info(
                                "Truncated size [{}] event to [{}] for authToken <[{}]>", modifiedData.length,
                                truncatedData.length, cfe16Token
                        );
            }

            // find appropriate targets for the routingKey
            Set<String> targets = routingLookup.getRoutes(hostname, appName);
            routingData = new RoutingData(truncatedData, targets);
            routed = true;
        }

        if (routingData.targets.isEmpty()) {
            routingData = new RoutingData(data, deadLetter.asSingletonSet());
        }

        LOGGER.debug("routing set for authToken <[{}]>: <{}>", cfe16Token, routingData.targets);
        if (!routed) {
            throw new IllegalStateException("routing logic failure aborting");
        }

        return routingData;
    }

    @Override
    public boolean validate() {
        boolean valid;
        try {
            rfc5424Frame.structuredData.getValue(authTokenVector);
            valid = true;
        }
        catch (NoSuchElementException nsee) {
            valid = false;
        }
        return valid;
    }
}
