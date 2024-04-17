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

import com.teragrep.cfe_35.router.targets.DeadLetter;
import com.teragrep.cfe_35.router.targets.Inspection;
import com.teragrep.rlo_06.RFC5424Frame;
import com.teragrep.rlo_11.key.AppName;
import com.teragrep.rlo_11.key.Hostname;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

public class CFE07RecordFrame implements Routeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(CFE07RecordFrame.class);

    final RFC5424Frame rfc5424Frame;

    final RoutingLookup routingLookup;

    final DeadLetter deadLetter;
    final Inspection inspection;

    CFE07RecordFrame(
            RoutingLookup routingLookup,
            RFC5424Frame rfc5424Frame,
            DeadLetter deadLetter,
            Inspection inspection
    ) {
        this.routingLookup = routingLookup;
        this.rfc5424Frame = rfc5424Frame;
        this.deadLetter = deadLetter;
        this.inspection = inspection;
    }

    @Override
    public RoutingData route(byte[] data) {
        // default to dead-letter
        RoutingData routingData = new RoutingData(data, deadLetter.asSingletonSet());
        boolean routed = false;

        Hostname hostname = new Hostname(rfc5424Frame.hostname.toString());
        AppName appName = new AppName(rfc5424Frame.appName.toString());

        if (!hostname.validate()) {
            // invalid -> inspection
            routingData = new RoutingData(data, inspection.asSingletonSet());
            LOGGER
                    .debug(
                            "routed hostname <[{}]> appName <[{}]> to <{}> due to hostname not valid",
                            hostname.hostname, appName.appName, inspection.asSingletonSet()
                    );
            routed = true;
        }

        if (!appName.validate()) {
            // replace appName with "" to be compatible with cfe-07
            AppName forcedAppName = new AppName("");
            LOGGER
                    .debug(
                            "changed hostname <[{}]> appName <[{}]> to forcedAppName <{}> due to appName not valid",
                            hostname.hostname, appName.appName, forcedAppName.appName
                    );
            appName = forcedAppName;
        }

        if (!routed) {
            if (!appName.equals(appName.asCompatible())) {
                // appName changed, log about it
                AppName compatibleAppName = appName.asCompatible();
                LOGGER
                        .info(
                                "changed appName from <[{}]> to compatibleAppName <[{}]>", appName.appName,
                                compatibleAppName.appName
                        );
                appName = compatibleAppName;
            }

            Set<String> targets = routingLookup.getRoutes(hostname, appName);
            routingData = new RoutingData(data, targets);

            routed = true;
        }

        if (routingData.targets.isEmpty()) {
            routingData = new RoutingData(data, deadLetter.asSingletonSet());
        }
        LOGGER
                .debug(
                        "routing set for hostname <[{}]> appName <[{}]>: <{}>", hostname.hostname, appName.appName,
                        routingData.targets
                );
        if (!routed) {
            throw new IllegalStateException("routing logic failure aborting");
        }

        return routingData;
    }
}
