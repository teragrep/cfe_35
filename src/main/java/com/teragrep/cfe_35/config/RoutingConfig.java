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
package com.teragrep.cfe_35.config;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.teragrep.cfe_35.config.json.TargetConfig;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.Map;
import java.util.Properties;

public class RoutingConfig {

    // server threads
    private final int serverThreads;

    // relp input
    private final int listenPort;

    // lookups
    private final String cfe07Lookup;
    private final String cfe16Lookup;
    private final String kin02Lookup;

    // routing targets
    private final Map<String, TargetConfig> targetConfigMap;

    // Prometheus stats
    private final int prometheusPort;

    // truncation
    private final int kin02TruncationLength;
    private final int cfe16TruncationLength;

    // Timeouts and intervals
    private final int connectionTimeout;
    private final int readTimeout;
    private final int writeTimeout;
    private final int reconnectInterval;

    public RoutingConfig() throws IOException {
        Properties properties = System.getProperties();

        // server threads
        String serverThreadsString = properties.getProperty("serverThreads", "1");
        this.serverThreads = Integer.parseInt(serverThreadsString);

        // relp input
        String listenPortString = properties.getProperty("listenPort", "1601");
        this.listenPort = Integer.parseInt(listenPortString);

        // lookups
        this.cfe07Lookup = properties.getProperty("cfe07LookupPath", "cfe07Lookups/");
        this.cfe16Lookup = properties.getProperty("cfe16LookupPath", "cfe16Lookups/");
        this.kin02Lookup = properties.getProperty("kin02LookupPath", "kin02Lookups/");

        // routing targets>
        try (FileReader fileReader = new FileReader(properties.getProperty("routingTargetsConfig", "targets.json"))) {
            try (BufferedReader bufferedReader = new BufferedReader(fileReader)) {
                Gson gson = new Gson();
                targetConfigMap = gson.fromJson(bufferedReader, new TypeToken<Map<String, TargetConfig>>() {
                }.getType());
            }
        }

        // Prometheus stats
        String prometheusPortString = properties.getProperty("prometheusPort", "1234");
        this.prometheusPort = Integer.parseInt(prometheusPortString);

        // truncation
        String kin02TruncationLengthString = properties
                .getProperty("kin02TruncationLength", String.valueOf(Integer.MAX_VALUE));
        this.kin02TruncationLength = Integer.parseInt(kin02TruncationLengthString);

        String cfe16TruncationLengthString = properties
                .getProperty("cfe16TruncationLength", String.valueOf(Integer.MAX_VALUE));
        this.cfe16TruncationLength = Integer.parseInt(cfe16TruncationLengthString);

        // Timeouts and intervals
        connectionTimeout = Integer.parseInt(properties.getProperty("connectionTimeout", "5000"));
        readTimeout = Integer.parseInt(properties.getProperty("readTimeout", "2500"));
        writeTimeout = Integer.parseInt(properties.getProperty("writeTimeout", "1500"));
        reconnectInterval = Integer.parseInt(properties.getProperty("reconnectInterval", "1000"));
    }

    public int getServerThreads() {
        return serverThreads;
    }

    public int getListenPort() {
        return listenPort;
    }

    public String getCfe16Lookup() {
        return cfe16Lookup;
    }

    public String getKin02Lookup() {
        return kin02Lookup;
    }

    public String getCfe07Lookup() {
        return cfe07Lookup;
    }

    public Map<String, TargetConfig> getTargetConfigMap() {
        return targetConfigMap;
    }

    public int getPrometheusPort() {
        return prometheusPort;
    }

    public int getKin02TruncationLength() {
        return kin02TruncationLength;
    }

    public int getCfe16TruncationLength() {
        return cfe16TruncationLength;
    }

    public int getConnectionTimeout() {
        return connectionTimeout;
    }

    public int getReadTimeout() {
        return readTimeout;
    }

    public int getWriteTimeout() {
        return writeTimeout;
    }

    public int getReconnectInterval() {
        return reconnectInterval;
    }
}
