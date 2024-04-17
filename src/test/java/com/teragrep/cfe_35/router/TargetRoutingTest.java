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

import com.codahale.metrics.MetricRegistry;
import com.teragrep.cfe_35.config.RoutingConfig;
import com.teragrep.rlp_03.FrameContext;
import com.teragrep.rlp_03.ServerFactory;
import com.teragrep.rlp_03.config.Config;
import com.teragrep.rlp_03.Server;
import com.teragrep.rlp_03.delegate.DefaultFrameDelegate;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class TargetRoutingTest {

    private final List<byte[]> spoolList = new ArrayList<>();
    private final List<byte[]> inspectionList = new ArrayList<>();
    private final List<byte[]> siem0List = new ArrayList<>();
    private final List<byte[]> hdfsList = new ArrayList<>();
    private final List<byte[]> deadLetterList = new ArrayList<>();

    private final MetricRegistry metricRegistry = new MetricRegistry();

    @BeforeAll
    public void setupTargets() throws IOException {
        setup(2601, spoolList);
        setup(2602, inspectionList);
        setup(2603, siem0List);
        setup(2604, hdfsList);
        setup(2605, deadLetterList);
    }

    private void setup(int port, List<byte[]> recordList) throws IOException {
        Consumer<FrameContext> cbFunction = relpFrameServerRX -> recordList
                .add(relpFrameServerRX.relpFrame().payload().toBytes());
        Config config = new Config(port, 1);
        ServerFactory serverFactory = new ServerFactory(config, () -> new DefaultFrameDelegate(cbFunction));
        Server server = serverFactory.create();
        Thread serverThread = new Thread(server);
        serverThread.start();
    }

    @Test
    public void testSpool() throws IOException {
        System.setProperty("routingTargetsConfig", "src/test/resources/targets.json");
        RoutingConfig routingConfig = new RoutingConfig();
        try (TargetRouting targetRouting = new ParallelTargetRouting(routingConfig, this.metricRegistry)) {
            targetRouting
                    .route(new RoutingData("test1".getBytes(StandardCharsets.UTF_8), Collections.singleton("spool")));
        }

        Assertions.assertEquals("test1", new String(spoolList.get(0), StandardCharsets.UTF_8));
        spoolList.clear();

    }

    @Test
    public void testFailed() throws IOException {
        System.setProperty("routingTargetsConfig", "src/test/resources/targets.json");
        RoutingConfig routingConfig = new RoutingConfig();
        try (TargetRouting targetRouting = new ParallelTargetRouting(routingConfig, this.metricRegistry)) {
            Assertions.assertThrows(IllegalArgumentException.class, () -> {
                targetRouting
                        .route(new RoutingData("test2".getBytes(StandardCharsets.UTF_8), Collections.singleton("no-such-thing")));
            }, "no such target <[no-such-thing]>");
        }

    }

    @Test
    public void testInspection() throws IOException {
        System.setProperty("routingTargetsConfig", "src/test/resources/targets.json");
        RoutingConfig routingConfig = new RoutingConfig();

        try (TargetRouting targetRouting = new ParallelTargetRouting(routingConfig, this.metricRegistry)) {
            targetRouting
                    .route(new RoutingData("test3".getBytes(StandardCharsets.UTF_8), Collections.singleton("inspection")));
        }

        Assertions.assertEquals("test3", new String(inspectionList.get(0), StandardCharsets.UTF_8));
        inspectionList.clear();
    }

    @Test
    public void testSiem0() throws IOException {
        System.setProperty("routingTargetsConfig", "src/test/resources/targets.json");
        RoutingConfig routingConfig = new RoutingConfig();

        try (TargetRouting targetRouting = new ParallelTargetRouting(routingConfig, this.metricRegistry)) {
            targetRouting
                    .route(new RoutingData("test4".getBytes(StandardCharsets.UTF_8), Collections.singleton("siem0")));
        }

        Assertions.assertEquals("test4", new String(siem0List.get(0), StandardCharsets.UTF_8));
        siem0List.clear();
    }

    @Test
    public void testHDFS() throws IOException {
        System.setProperty("routingTargetsConfig", "src/test/resources/targets.json");
        RoutingConfig routingConfig = new RoutingConfig();
        try (TargetRouting targetRouting = new ParallelTargetRouting(routingConfig, this.metricRegistry)) {
            targetRouting
                    .route(new RoutingData("test5".getBytes(StandardCharsets.UTF_8), Collections.singleton("hdfs")));
        }

        Assertions.assertEquals("test5", new String(hdfsList.get(0), StandardCharsets.UTF_8));
        hdfsList.clear();
    }

    @Test
    public void testDeadLetter() throws IOException {
        System.setProperty("routingTargetsConfig", "src/test/resources/targets.json");
        RoutingConfig routingConfig = new RoutingConfig();
        try (TargetRouting targetRouting = new ParallelTargetRouting(routingConfig, this.metricRegistry)) {
            targetRouting
                    .route(new RoutingData("test6".getBytes(StandardCharsets.UTF_8), Collections.singleton("dead-letter")));
        }

        Assertions.assertEquals("test6", new String(deadLetterList.get(0), StandardCharsets.UTF_8));
        deadLetterList.clear();
    }
}
