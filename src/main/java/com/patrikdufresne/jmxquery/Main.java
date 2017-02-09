/**
 * Copyright(C) 2016 Patrik Dufresne Service Logiciel <info@patrikdufresne.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package com.patrikdufresne.jmxquery;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.management.JMException;
import javax.management.MBeanServerConnection;
import javax.management.ObjectName;
import javax.management.openmbean.CompositeDataSupport;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;

import org.rrd4j.ConsolFun;
import org.rrd4j.DsType;
import org.rrd4j.core.FetchData;
import org.rrd4j.core.FetchRequest;
import org.rrd4j.core.RrdDb;
import org.rrd4j.core.RrdDef;
import org.rrd4j.core.RrdSafeFileBackendFactory;
import org.rrd4j.core.Sample;
import org.rrd4j.core.Util;

public class Main {

    /**
     * Raised when arguments cannot be parsed.
     * 
     * @author Patrik Dufresne
     *
     */
    static class ParseError extends Exception {

        public ParseError(Exception e) {
            super(e);
        }

    }

    private static class Range {
        public static Range createRange(SeverityLevel level, String range) {
            Range t = new Range();
            t.level = level;
            if (range.startsWith("^")) {
                t.invert = true;
                range = range.substring(1);
            }

            String[] args = range.split("\\.\\.");

            t.start = parseNumber(args[0]);
            t.end = Double.MAX_VALUE;
            if (args.length == 2) {
                t.end = parseNumber(args[1]);
            }
            return t;
        }

        public static Range createRegex(SeverityLevel level, String regex) {
            Range t = new Range();
            t.level = level;
            if (regex.startsWith("^")) {
                t.invert = true;
                regex = regex.substring(1);
            }
            t.regex = Pattern.compile(regex);
            return t;
        }

        private static double parseNumber(String value) {
            if (value.endsWith("inf")) {
                return value.startsWith("-") ? Double.MIN_VALUE : Double.MAX_VALUE;
            }
            if (value.isEmpty()) return Double.MAX_VALUE;
            try {
                return Double.parseDouble(value);
            } catch (NumberFormatException e) {
            }
            throw new IllegalArgumentException("invalid number: " + value);
        }

        private double end;
        private boolean invert;

        private SeverityLevel level;

        private Pattern regex;

        private double start;

        public boolean inRange(Object value) {
            if (value == null) return false;
            boolean result = false;
            if (regex != null) {
                result = regex.matcher(value.toString()).matches();
            }
            if ((value instanceof Number)) {
                result = (start <= ((Number) value).doubleValue()) && (((Number) value).doubleValue() <= end);
            }
            return invert ? !result : result;
        }
    }

    private static enum SeverityLevel {
        CRITICAL(2), OK(0), UNKNOWN(3), WARNING(1);

        public static SeverityLevel max(SeverityLevel l1, SeverityLevel l2) {
            return l1.returnCode >= l2.returnCode ? l1 : l2;
        }

        public int returnCode;

        private SeverityLevel(int returnCode) {
            this.returnCode = returnCode;
        }
    }

    /**
     * Represent a threshold defined from command line to be retrieve via JMX.
     * 
     * @author Patrik Dufresne
     *
     */
    private static class ThresholdDefinition {

        private static final String RRD = ".rrd";

        /**
         * Create a new threshold definition from comment line arguments.
         * 
         * @param object
         *            the JMX object name.
         * @param arguments
         *            the arguments defining the attributes to be fetched and the optional threshold.
         * @return a new threshold definition.
         */
        public static ThresholdDefinition create(Main main, String object, String arguments) {
            ThresholdDefinition att = new ThresholdDefinition();
            att.main = main;
            att.object = object;
            String[] args = arguments.split(",|=");
            for (int i = 0; i < args.length; i++) {
                if (args[i].equals("metric")) att.attribute = args[(++i)];
                else if ((args[i].equals("w")) || (args[i].equals("warn")) || (args[i].equals("warning")))
                    att.addThreshold(Range.createRange(SeverityLevel.WARNING, args[(++i)]));
                else if ((args[i].equals("c")) || (args[i].equals("crit")) || (args[i].equals("critical")))
                    att.addThreshold(Range.createRange(SeverityLevel.CRITICAL, args[(++i)]));
                else if ((args[i].equals("regex-warn")) || (args[i].equals("regex-warning")))
                    att.addThreshold(Range.createRegex(SeverityLevel.WARNING, args[(++i)]));
                else if ((args[i].equals("regex-crit")) || (args[i].equals("regex-critical")))
                    att.addThreshold(Range.createRegex(SeverityLevel.CRITICAL, args[(++i)]));
                else if (args[i].equals("unit")) att.unit = args[(++i)];
                else if ((args[i].equals("d")) || (args[i].equals("desc")) || (args[i].equals("description"))) att.description = args[(++i)];
                else if ((args[i].equals("l")) || (args[i].equals("label"))) att.label = args[(++i)];
                else if ((args[i].equals("avg")) || (args[i].equals("average"))) att.average = Integer.valueOf(Integer.parseInt(args[(++i)]));
            }
            return att;
        }

        public Main main;
        public String attribute;
        public String description;
        public String label;
        private String object;
        public List<Range> ranges;
        public int average;

        public String unit;

        private void addThreshold(Range create) {
            if (ranges == null) {
                ranges = new ArrayList<Range>();
            }
            ranges.add(create);
        }

        /**
         * Create a threshold value using this threshold definition as a basis.
         * 
         * @param object
         *            the value (may be null)
         * @return the threshold value.
         */
        public ThresholdValue createValue(String name, Object value) {
            ThresholdValue tv = new ThresholdValue();
            tv.attribute = this.attribute;
            tv.description = this.description;
            if (this.label != null && isGlobPattern(tv.attribute)) {
                Pattern p = Pattern.compile("^.*" + globToRegex(tv.attribute));
                Matcher m = p.matcher(name);
                tv.label = m.replaceFirst(this.label);
            } else if (this.label != null) {
                tv.label = this.label;
            } else {
                tv.label = name;
            }
            tv.ranges = this.ranges;
            tv.unit = this.unit;

            // Check if this value need to be average using RRD
            if (this.average > 0 && value instanceof Number) {
                tv.value = getRate(tv.label, ((Number) value).doubleValue(), this.average);
            } else {
                tv.value = value;
            }

            return tv;
        }

        /**
         * Convert the given value into a rate (per seconds) using RRD.
         * 
         * @param value
         *            the new value to be added to RRD.
         * @param rate
         *            the time length to be used to compute average rate.
         * @return the value or null if not enough data to compute rate.
         */
        private Double getRate(String name, double value, int rate) {
            RrdDb rrdDb = null;
            Sample sample = null;
            String filename = name + "_hash" + Math.abs(main.url.hashCode());
            try {
                long start = Util.getTimestamp();
                new File(RRD).mkdir();
                File file = new File(RRD, filename);
                if (!file.isFile()) {
                    RrdDef rrdDef = new RrdDef(file.getAbsolutePath(), start - 1L, 300L);
                    rrdDef.setVersion(2);
                    rrdDef.addDatasource("data", DsType.COUNTER, 300L, Double.NaN, Double.NaN);
                    rrdDef.addArchive(ConsolFun.AVERAGE, 0.5D, 1, 120);
                    rrdDb = new RrdDb(rrdDef, new RrdSafeFileBackendFactory());
                } else {
                    rrdDb = new RrdDb(file.getAbsolutePath(), new RrdSafeFileBackendFactory());
                }
                sample = rrdDb.createSample();
                sample.setTime(start);
                sample.setValue("data", value);
                sample.update();

                // Fetch the value.
                long now = Util.getTimestamp();
                FetchRequest request = rrdDb.createFetchRequest(ConsolFun.AVERAGE, now - rate, now);
                FetchData fetchData = request.fetchData();
                return Double.valueOf(fetchData.getAggregate("data", ConsolFun.AVERAGE));

            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                try {
                    rrdDb.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            return null;
        }

        public String name() {
            if (label != null) {
                return label;
            }
            return new StringBuilder().append(object).append(".").append(attribute).toString().replaceAll("[:,]\\w+=", "_");
        }

    }

    /**
     * Represent the threshold value (retrived from JMX).
     * 
     * @author Patrik Dufresne
     *
     */
    private static class ThresholdValue extends ThresholdDefinition {

        private Object value;

        public SeverityLevel inRange() {
            if (ranges == null) {
                return SeverityLevel.OK;
            }
            SeverityLevel level = SeverityLevel.OK;
            for (Range r : ranges) {
                if (value == null || value().equals(Double.NaN)) {
                    level = SeverityLevel.max(level, SeverityLevel.CRITICAL);
                } else if (r.inRange(value)) {
                    level = SeverityLevel.max(level, r.level);
                }
            }
            return level;
        }

        public String value() {
            String string = "";
            if (((value instanceof Float)) || ((value instanceof Double)))
                string = new StringBuilder().append(string).append(String.format("%.4f", new Object[] { value })).toString();
            else {
                string = new StringBuilder().append(string).append(value).toString();
            }
            if (value != null && !value.equals(Double.NaN)) {
                string = new StringBuilder().append(string).append(unit != null ? unit.toString() : "").toString();
            }
            return string;
        }

    }

    /**
     * Attempts to match the entire region against the pattern.
     * 
     * @param pattern
     *            glob pattern
     * @param input
     *            the input string to be validated.
     */
    public static boolean globMatches(String pattern, String input) {
        Pattern p = Pattern.compile(globToRegex(pattern));
        return p.matcher(input).matches();
    }

    /**
     * Converts a basic globing pattern regular expression pattern. This glob only support * and ?.
     * 
     * @param pattern
     *            A glob pattern.
     * @return A regex pattern to recognize the given glob pattern.
     */
    public static final String globToRegex(String pattern) {
        StringBuilder sb = new StringBuilder(pattern.length());
        char[] arr = pattern.toCharArray();
        for (int i = 0; i < arr.length; i++) {
            char ch = arr[i];
            switch (ch) {
            case '*':
                sb.append("(.*)");
                break;
            case '?':
                sb.append("(.)");
                break;
            case '\\':
            case '.':
            case '(':
            case ')':
            case '+':
            case '|':
            case '^':
            case '$':
            case '@':
            case '%':
                sb.append('\\');
                sb.append(ch);
                break;
            default:
                sb.append(ch);
            }
        }
        return sb.toString();
    }

    /**
     * Return true if the given string is a glob pattern.
     * 
     * @return
     */
    public static boolean isGlobPattern(String pattern) {
        return pattern.contains("?") || pattern.contains("*");
    }

    public static void main(String[] args) {
        Main query = new Main();
        try {
            query.parseArguments(args);
            query.connect();
            List<ThresholdValue> values = query.retrieveAttributesValue();
            int status = query.report(values);
            System.exit(status);
        } catch (Exception ex) {
            int status = query.reportError(ex, System.out);
            System.exit(status);
        } finally {
            try {
                query.disconnect();
            } catch (IOException e) {
                int status = query.reportError(e, System.out);
                System.exit(status);
            }
        }
    }

    /**
     * Recursively get the property from the object.
     * 
     * @param value
     *            the attribute value
     * @param property
     *            the property to be fetch from the object, like objectname, this property may include * or ? wildcard.
     */
    public static Map<String, Object> readProperties(Object value, String properties, String prefix) {
        String property = substringBefore(properties, ".");
        String nextProperty = substringAfter(properties, ".");

        Map<String, Object> values = new LinkedHashMap<String, Object>();
        if (!property.isEmpty() && value instanceof CompositeDataSupport) {
            CompositeDataSupport cds = (CompositeDataSupport) value;
            for (String key : cds.getCompositeType().keySet()) {
                if (globMatches(property, key)) {
                    Map<String, Object> map = readProperties(unbox(cds.get(key)), nextProperty, prefix + "." + key);
                    for (Entry<String, Object> e : map.entrySet()) {
                        values.put(e.getKey(), e.getValue());
                    }
                }
            }
        } else if (!property.isEmpty() && value instanceof Map) {
            Map<String, Object> cds = (Map<String, Object>) value;
            for (String key : cds.keySet()) {
                if (globMatches(property, key)) {
                    Map<String, Object> map = readProperties(unbox(cds.get(key)), nextProperty, prefix + "." + key);
                    for (Entry<String, Object> e : map.entrySet()) {
                        values.put(e.getKey(), e.getValue());
                    }
                }
            }
        } else {
            values.put(prefix, unbox(value));
        }
        return values;
    }

    /**
     * Gets the substring after the first occurrence of a separator. The separator is not returned.
     * 
     * @param str
     * @param separator
     * @return
     */
    public static String substringAfter(final String str, final String separator) {
        if (str == null || str.isEmpty()) {
            return str;
        }
        if (separator == null) {
            return "";
        }
        final int pos = str.indexOf(separator);
        if (pos == -1) {
            return "";
        }
        return str.substring(pos + separator.length());
    }

    /**
     * Gets the substring before the first occurrence of a separator. The separator is not returned
     * 
     * @param str
     * @param separator
     * @return
     */
    public static String substringBefore(final String str, final String separator) {
        if (str == null || str.isEmpty() || separator == null) {
            return str;
        }
        if (separator.isEmpty()) {
            return "";
        }
        final int pos = str.indexOf(separator);
        if (pos == -1) {
            return str;
        }
        return str.substring(0, pos);
    }

    /**
     * Used to unbox the value returned by JMX query.
     * 
     * In too many cases, the JMX query return a string while the value is a number or a map. This method will try to
     * guess the format and return a new object to represent the value.
     * 
     * @param o
     *            the input value.
     * @return the converted attribute value.
     */
    public static Object unbox(Object o) {
        if (o == null) {
            return null;
        }
        if ((o instanceof Number)) {
            return o;
        } else if (((o instanceof String)) && (o.toString().endsWith("%"))) {
            return Long.valueOf(Double.valueOf(o.toString().substring(0, o.toString().length() - 1)).longValue());
        }
        try {
            return Long.valueOf(Long.parseLong(o.toString()));
        } catch (NumberFormatException e) {
            // Swallow number format exception.
        }
        // Drools return a string like attributename=value seperated by space.
        Map<String, Object> table = new HashMap<String, Object>();
        Pattern p = Pattern.compile("([a-zA-Z\\-]+)=([0-9]+)(ms)?");
        Matcher m = p.matcher(o.toString());
        while (m.find()) {
            table.put(m.group(1), unbox(m.group(2)));
        }
        if (!table.isEmpty()) {
            return table;
        }
        return o.toString();
    }

    private LinkedList<ThresholdDefinition> attributes = new LinkedList<ThresholdDefinition>();

    private MBeanServerConnection connection;

    private JMXConnector connector;

    private String password;

    private PrintStream stdout = System.out;

    private String url;

    private String username;

    private int verbatim;

    private void connect() throws IOException {
        Map<String, Object> hm = null;
        if ((username != null) && (password != null)) {
            hm = new HashMap<String, Object>();
            hm.put("jmx.remote.credentials", new String[] { username, password });
        }

        JMXServiceURL jmxUrl = new JMXServiceURL(url);
        connector = JMXConnectorFactory.connect(jmxUrl, hm);
        connection = connector.getMBeanServerConnection();
    }

    private void disconnect() throws IOException {
        if (connector != null) {
            connector.close();
            connector = null;
        }
    }

    private void parseArguments(String[] args) throws ParseError {
        try {
            String object = null;
            for (int i = 0; i < args.length; i++) {
                String option = args[i];
                if (option.equals("--help") || option.equals("-h")) {
                    printHelp(System.out);
                    System.exit(SeverityLevel.UNKNOWN.returnCode);
                } else if (option.equals("-u")) {
                    username = args[(++i)];
                } else if (option.equals("-p")) {
                    password = args[(++i)];
                } else if (option.equals("-U")) {
                    url = args[(++i)];
                } else if (option.equals("-O")) {
                    object = args[(++i)];
                } else if (option.startsWith("-v")) {
                    verbatim = (option.length() - 1);
                } else if ((option.equals("--threshold")) || (option.equals("--th"))) {
                    if (object == null) throw new IllegalArgumentException(new StringBuilder().append("-O need to set before ").append(option).toString());
                    attributes.add(ThresholdDefinition.create(this, object, args[(++i)]));
                }
            }
            // Check if argument is missing.
            if (url == null) {
                throw new Exception("Required options -U not specified");
            } else if (object == null) {
                throw new Exception("Required options -O not specified");
            } else if (attributes == null) {
                throw new Exception("Required options --th not specified");
            }

        } catch (Exception e) {
            throw new ParseError(e);
        }
    }

    private void printHelp(PrintStream out) {
        InputStream is = getClass().getClassLoader().getResourceAsStream("org/nagios/Help.txt");
        BufferedReader reader = new BufferedReader(new InputStreamReader(is));
        try {
            while (true) {
                String s = reader.readLine();
                if (s == null) break;
                out.println(s);
            }
        } catch (IOException e) {
            out.println(e);
        } finally {
            try {
                reader.close();
            } catch (IOException e) {
                out.println(e);
            }
        }
    }

    /**
     * Based on the threshold value, determine the state of the service (CRITICAL, WARNING, OK, UNKNOWN) and print the
     * performance data.
     * 
     * @param values
     * @return
     * @throws ParseError
     */
    private int report(Collection<ThresholdValue> values) throws ParseError {
        StringBuilder perf = new StringBuilder();
        StringBuilder out = new StringBuilder();

        SeverityLevel status = SeverityLevel.OK;
        for (ThresholdValue att : values) {
            SeverityLevel level = att.inRange();
            status = SeverityLevel.max(status, level);
            if (!SeverityLevel.OK.equals(level)) {
                if (out.length() != 0) out.append(", ");
                if (att.description != null) out.append(att.description);
                out.append(new StringBuilder().append(att.name()).append(": ").append(att.value()).toString());
            }

            if (att.value instanceof Number && !att.value.equals(Double.NaN)) {
                if (perf.length() != 0) perf.append(" ");
                perf.append(new StringBuilder().append(att.name()).append("=").append(att.value()).toString());
            }
        }

        stdout.print(new StringBuilder().append("JMX ").append(status.name()).append(" ").toString());
        stdout.print(out);

        stdout.append("|");
        stdout.append(perf);
        stdout.println();
        return status.returnCode;
    }

    private int reportError(Exception ex, PrintStream out) {
        out.print(new StringBuilder().append(SeverityLevel.UNKNOWN.name()).append(" ").toString());
        out.println(ex.toString());
        if ((ex instanceof ParseError)) {
            out.print("Usage: check_jmx --help");
        }
        out.println();

        if (verbatim >= 3) ex.printStackTrace(out);

        return SeverityLevel.UNKNOWN.returnCode;
    }

    /**
     * Execute the JMX query to retrieve the attributes for each threshold definition.
     * 
     * @return list of threshold value retrieved for each threshold definition.
     * 
     * @throws Exception
     */
    private List<ThresholdValue> retrieveAttributesValue() throws Exception {
        // For each threshold definition, try to capture the attribute value from JMX.
        List<ThresholdValue> values = new ArrayList<ThresholdValue>();
        for (ThresholdDefinition att : attributes) {
            String property = substringBefore(att.attribute, ".");
            String nextProperty = substringAfter(att.attribute, ".");
            try {
                // Query list of MBean object name matching our patterns.
                Set<ObjectName> names = connection.queryNames(new ObjectName(att.object), null);
                // For each object name, get the attribute value and unbox it.
                for (ObjectName name : names) {
                    Object value = connection.getAttribute(name, property);
                    Map<String, Object> map = readProperties(value, nextProperty, name.toString() + "." + property);
                    for (Entry<String, Object> e : map.entrySet()) {
                        values.add(att.createValue(e.getKey(), e.getValue()));
                    }
                }
            } catch (JMException e) {
                values.add(att.createValue(property, null));
            }
        }
        return values;
    }

}