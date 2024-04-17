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
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class RecordFrameCfe16Test {

    private RoutingLookup routingLookup;
    private RoutingConfig routingConfig;

    @BeforeAll
    public void bootstrap() throws IOException {
        System.setProperty("routingTargetsConfig", "src/test/resources/targetsRecordFrameTest.json");
        System.setProperty("cfe07LookupPath", "src/test/resources/cfe_07");
        System.setProperty("cfe16LookupPath", "src/test/resources/cfe_16");
        System.setProperty("kin02LookupPath", "src/test/resources/kin_02");

        routingConfig = new RoutingConfig();
        routingLookup = new RoutingLookup(routingConfig);
    }

    @Test
    public void testCfe16RouteSuccess() throws IOException {
        RFC5424Frame rfc5424Frame = new RFC5424Frame();
        CFE16RecordFrame cfe16RecordFrame = new CFE16RecordFrame(
                routingLookup,
                rfc5424Frame,
                routingConfig,
                new DeadLetter(),
                new Inspection()
        );

        byte[] spoolMessage = "<14>1 2023-08-07T08:39:43.196Z CFE-16 capsulated - - [CFE-16-metadata@48577 authentication_token=\"My RoutingKey having token\" channel=\"defaultchannel\" time_source=\"generated\"][CFE-16-origin@48577 X-Forwarded-For=\"127.0.0.3\" X-Forwarded-Host=\"127.0.0.2\" X-Forwarded-Proto=\"http\"] \"Testing\""
                .getBytes(StandardCharsets.UTF_8);

        ByteArrayInputStream bais = new ByteArrayInputStream(spoolMessage);
        rfc5424Frame.load(bais);
        Assertions.assertTrue(rfc5424Frame.next());

        RoutingData routingData = cfe16RecordFrame.route(spoolMessage);

        Assertions.assertEquals(Collections.singleton("spool"), routingData.targets);
    }

    @Test
    public void testCfe16RouteFailure() throws IOException {
        RFC5424Frame rfc5424Frame = new RFC5424Frame();
        CFE16RecordFrame cfe16RecordFrame = new CFE16RecordFrame(
                routingLookup,
                rfc5424Frame,
                routingConfig,
                new DeadLetter(),
                new Inspection()
        );

        byte[] spoolMessage = "<14>1 2023-08-07T08:39:43.196Z CFE-16 capsulated - - [CFE-16-metadata@48577 authentication_token=\"This token does not exist\" channel=\"defaultchannel\" time_source=\"generated\"][CFE-16-origin@48577 X-Forwarded-For=\"127.0.0.3\" X-Forwarded-Host=\"127.0.0.2\" X-Forwarded-Proto=\"http\"] \"Testing\""
                .getBytes(StandardCharsets.UTF_8);

        ByteArrayInputStream bais = new ByteArrayInputStream(spoolMessage);
        rfc5424Frame.load(bais);
        Assertions.assertTrue(rfc5424Frame.next());

        RoutingData routingData = cfe16RecordFrame.route(spoolMessage);

        Assertions.assertEquals(Collections.singleton("dead-letter"), routingData.targets);
    }

    @Test
    public void testCfe16InvalidHostname() throws IOException {
        RFC5424Frame rfc5424Frame = new RFC5424Frame();
        CFE16RecordFrame cfe16RecordFrame = new CFE16RecordFrame(
                routingLookup,
                rfc5424Frame,
                routingConfig,
                new DeadLetter(),
                new Inspection()
        );

        byte[] spoolMessage = "<14>1 2023-08-07T08:39:43.196Z ^_^ capsulated - - [CFE-16-metadata@48577 authentication_token=\"Returns invalid hostname\" channel=\"defaultchannel\" time_source=\"generated\"][CFE-16-origin@48577 X-Forwarded-For=\"127.0.0.3\" X-Forwarded-Host=\"127.0.0.2\" X-Forwarded-Proto=\"http\"] \"Testing\""
                .getBytes(StandardCharsets.UTF_8);

        ByteArrayInputStream bais = new ByteArrayInputStream(spoolMessage);
        rfc5424Frame.load(bais);
        Assertions.assertTrue(rfc5424Frame.next());

        RoutingData routingData = cfe16RecordFrame.route(spoolMessage);

        Assertions.assertEquals(Collections.singleton("inspection"), routingData.targets);
    }

    @Test
    public void testCfe16NonroutedHostname() throws IOException {
        RFC5424Frame rfc5424Frame = new RFC5424Frame();
        CFE16RecordFrame cfe16RecordFrame = new CFE16RecordFrame(
                routingLookup,
                rfc5424Frame,
                routingConfig,
                new DeadLetter(),
                new Inspection()
        );

        byte[] spoolMessage = "<14>1 2023-08-07T08:39:43.196Z i-am-not-routed capsulated - - [CFE-16-metadata@48577 authentication_token=\"My RoutingKey with no hostname\" channel=\"defaultchannel\" time_source=\"generated\"][CFE-16-origin@48577 X-Forwarded-For=\"127.0.0.3\" X-Forwarded-Host=\"127.0.0.2\" X-Forwarded-Proto=\"http\"] \"Testing\""
                .getBytes(StandardCharsets.UTF_8);

        ByteArrayInputStream bais = new ByteArrayInputStream(spoolMessage);
        rfc5424Frame.load(bais);
        Assertions.assertTrue(rfc5424Frame.next());

        RoutingData routingData = cfe16RecordFrame.route(spoolMessage);

        Assertions.assertEquals(Collections.singleton("dead-letter"), routingData.targets);
    }
}
