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
import com.teragrep.rlo_11.cfe_07.CFE07Routing;
import com.teragrep.rlo_11.cfe_16.CFE16Routing;
import com.teragrep.rlo_11.key.AppName;
import com.teragrep.rlo_11.key.Hostname;
import com.teragrep.rlo_11.kin_02.KIN02Routing;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

public class RoutingLookup {

    CFE07Routing cfe07Routing;
    KIN02Routing kin02Routing;
    CFE16Routing cfe16Routing;

    RoutingLookup(RoutingConfig routingConfig) throws IOException {
        DeadLetter deadLetter = new DeadLetter();
        Inspection inspection = new Inspection();

        // TODO create paths
        Set<String> targets = new HashSet<>();
        routingConfig.getTargetConfigMap().forEach((k, v) -> {
            // Do not process lookups if not enabled or if they are dead-letter/inspection

            if (v.isEnabled() && !k.equals(deadLetter.name) && !k.equals(inspection.name)) {
                targets.add(k);
            }
        });
        cfe07Routing = new CFE07Routing(routingConfig.getCfe07Lookup(), targets);
        cfe16Routing = new CFE16Routing(routingConfig.getCfe16Lookup());
        kin02Routing = new KIN02Routing(routingConfig.getKin02Lookup());
    }

    public Hostname getHostnameForToken(String token) {
        return cfe16Routing.getHostname(token);
    }

    public AppName getAppNameForToken(String token) {
        return cfe16Routing.getAppName(token);
    }

    public Set<String> getRoutes(Hostname hostname, AppName appName) {
        return cfe07Routing.getTargets(hostname, appName);
    }

    public Hostname getHostnameForAccount(String account) {
        return kin02Routing.getHostname(account);
    }

    public AppName getAppNameForLogGroup(String logGroup) {
        return kin02Routing.getAppName(logGroup);
    }
}
