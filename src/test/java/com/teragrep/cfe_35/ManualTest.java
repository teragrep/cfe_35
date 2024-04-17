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
package com.teragrep.cfe_35;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

public class ManualTest {

    @Test
    @EnabledIfSystemProperty(
            named = "runManualTest",
            matches = "true"
    )
    public void manualTest() throws Exception {
        // relp input
        System.setProperty("listenPort", "1601");
        Main.main(null);

        /*
        <134>1 2021-01-20T11:59:55.590353+00:00 127.0.0.2 myAppName - - [event_id@48577 hostname="localhost" uuid="C4B61AAA6C954D0EB51195EEFD39745A" unixtime="1611143995" id_source="relay"][rfc3164@48577 syslogtag="myAppName:"][event_format@48577 original_format="rfc3164"][event_node_relay@48577 hostname="localhost" source="127.0.0.2" source_module="imudp"][event_version@48577 major="2" minor="2" hostname="localhost" version_source="relay"][event_node_router@48577 source="router.example.com" source_module="imrelp" hostname="localhost"] NetScreen device_id=myAppName  [Root]system-information-00536: IKE 127.0.0.1 Phase 1: Retransmission limit has been reached. (2021-01-20 13:59:56)
        
         */

        /*
        good:
        
        for prefix in group-one group-two common; do     for tag in one two; do         echo "Sending data using ${prefix}-host:${prefix}-tag-${tag} settings";         /opt/Fail-Safe/rsyslog/rsyslog/bin/tcpflood -s -t 127.0.0.1 -T relp-plain -p 1601 -m 1 -M "<13>1 2020-01-01T00:00:00+02:00 ${prefix}-host ${prefix}-tag-${tag} - - - I am ${prefix}-host and ${prefix}-tag-${tag}";     done; done;
         */

        /*
        broken (missing sd completely):
        
        for prefix in group-one group-two common; do     for tag in one two; do         echo "Sending data using ${prefix}-host:${prefix}-tag-${tag} settings";         /opt/Fail-Safe/rsyslog/rsyslog/bin/tcpflood -s -t 127.0.0.1 -T relp-plain -p 1601 -m 1 -M "<13>1 2020-01-01T00:00:00+02:00 ${prefix}-host ${prefix}-tag-${tag} - - I am ${prefix}-host and ${prefix}-tag-${tag}";     done; done;
         */
    }
}
