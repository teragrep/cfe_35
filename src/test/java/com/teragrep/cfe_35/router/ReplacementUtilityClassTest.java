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

import com.teragrep.rlo_06.RFC5424Frame;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public class ReplacementUtilityClassTest {

    @Test
    public void testHappyReplace() throws IOException {
        RFC5424Frame frame = new RFC5424Frame();
        String message = "<14>1 2023-08-23T10:21:00+03:00 old-hostname old-appname - - - msg\n";
        InputStream inputStream = new ByteArrayInputStream(message.getBytes());
        frame.load(inputStream);
        frame.next();
        Assertions.assertEquals("old-hostname", frame.hostname.toString(), "Hostname is not as expected");
        Assertions.assertEquals("old-appname", frame.appName.toString(), "Appname is not as expected");
        String replacementHostname = "new-hostname";
        String replacementAppname = "new-appname";
        String response = new String(ReplacementUtilityClass.replace(frame, replacementHostname, replacementAppname));
        Assertions
                .assertEquals(
                        "<14>1 2023-08-23T10:21:00+03:00 new-hostname new-appname - - - msg\n", response,
                        "Response did not replace values as expected"
                );
    }

    @Test
    public void testHappyReplaceWithSDParams() throws IOException {
        RFC5424Frame frame = new RFC5424Frame();
        String message = "<14>1 2023-08-23T10:21:00+03:00 old-hostname old-appname - - [first@48577 key=\"value\" secret=\"sosecret\"][second@48577 test=\"true\" failed=\"false\"] msg\n";
        InputStream inputStream = new ByteArrayInputStream(message.getBytes());
        frame.load(inputStream);
        frame.next();
        Assertions.assertEquals("old-hostname", frame.hostname.toString(), "Hostname is not as expected");
        Assertions.assertEquals("old-appname", frame.appName.toString(), "Appname is not as expected");
        String replacementHostname = "new-hostname";
        String replacementAppname = "new-appname";
        String response = new String(ReplacementUtilityClass.replace(frame, replacementHostname, replacementAppname));
        Assertions
                .assertEquals(
                        "<14>1 2023-08-23T10:21:00+03:00 new-hostname new-appname - - [first@48577 key=\"value\" secret=\"sosecret\"][second@48577 test=\"true\" failed=\"false\"] msg\n",
                        response, "Response did not replace values as expected"
                );
    }
}
