package Main;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.Assert.*;

public class ConfigLoaderTest {
    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    private ConfigLoader loader;

    @Before
    public void setUp() {
        loader = new ConfigLoader(temporaryFolder.getRoot().getAbsolutePath());
    }

    @Test
    public void savingDefaultConfigPreservesProfilesAndCommentsAcrossRepeatedSaves() {
        String original = loader.readConfigText();
        Object profiles = loader.loadConfig().get("profiles");
        assertNotNull(profiles);

        assertTrue(loader.saveGeneralConfig(8, 4, 0.75, "en"));
        assertGeneral(8, 4, 0.75, "en");
        assertEquals(profiles, loader.loadConfig().get("profiles"));
        assertEquals(original.substring(original.indexOf("profiles:")),
                loader.readConfigText().substring(loader.readConfigText().indexOf("profiles:")));
        assertTrue(loader.readConfigText().contains("8                    # 默认线程数"));
        assertTrue(loader.readConfigText().contains("en                      # 界面语言: zh | en"));

        assertTrue(loader.saveGeneralConfig(12, 5, 0.9, "zh"));
        assertGeneral(12, 5, 0.9, "zh");
        assertEquals(profiles, loader.loadConfig().get("profiles"));
    }

    @Test
    public void savingRepairsCommentSeparatorsDamagedByPreviousVersion() throws Exception {
        String original = loader.readConfigText();
        Object profiles = loader.loadConfig().get("profiles");
        int profilesStart = original.indexOf("profiles:");
        write(original.substring(0, profilesStart).replaceAll("[ \\t]+#", "#")
                + original.substring(profilesStart));
        assertTrue(loader.loadConfig().isEmpty());

        assertTrue(loader.saveGeneralConfig(8, 4, 0.75, "en"));
        assertGeneral(8, 4, 0.75, "en");
        assertEquals(profiles, loader.loadConfig().get("profiles"));
    }

    @Test
    public void commentsWithoutColonsDoNotTurnNumbersIntoStrings() throws Exception {
        write("general:\n"
                + "  threads: 5 # workers\n"
                + "  max_redirects: 3\t# hops\n"
                + "  similarity_threshold: 0.85 # threshold\n"
                + "  lang: zh # language\n"
                + "profiles: {}\n");

        assertTrue(loader.saveGeneralConfig(7, 2, 0.8, "en"));
        assertGeneral(7, 2, 0.8, "en");
        assertTrue(loader.readConfigText().contains("2\t# hops"));
    }

    @Test
    public void insertingMissingGeneralFieldsDoesNotDuplicateOrOverrideExistingFields() throws Exception {
        String[] fields = {"  threads: 5\n", "  max_redirects: 3\n",
                "  similarity_threshold: 0.85\n", "  lang: zh\n"};
        for (int missing = 0; missing < fields.length; missing++) {
            StringBuilder text = new StringBuilder("general:\n");
            for (int i = 0; i < fields.length; i++) {
                if (i != missing) text.append(fields[i]);
            }
            text.append("profiles: {}\n");
            write(text.toString());

            assertTrue(loader.saveGeneralConfig(9, 6, 0.7, "en"));
            assertGeneral(9, 6, 0.7, "en");
            assertEquals(1, loader.readConfigText().split("  lang:", -1).length - 1);
        }
    }

    @Test
    public void overloadPreservesLanguageAndMaxRedirects() throws Exception {
        write("general:\n"
                + "  threads: 5\n"
                + "  max_redirects: 6 # custom limit\n"
                + "  similarity_threshold: 0.85\n"
                + "  lang: en\n"
                + "profiles: {}\n");

        assertTrue(loader.saveGeneralConfig(10, 0.6));
        assertGeneral(10, 6, 0.6, "en");
    }

    @Test
    public void sharedScalarWriterPreservesWafBooleanAndNumberTypes() throws Exception {
        write("general: {threads: 5}\n"
                + "profiles:\n"
                + "  auto_waf_bypass:\n"
                + "    options:\n"
                + "      ghost_bits:\n"
                + "        enabled: false # switch\n"
                + "        raw_socket: true # sender\n"
                + "        max_variants: 10 # limit\n");
        Map<String, Object> ghost = new LinkedHashMap<>();
        ghost.put("enabled", true);
        ghost.put("raw_socket", false);
        ghost.put("max_variants", 8);

        assertTrue(loader.saveWafOptions(Collections.<String, Object>singletonMap("ghost_bits", ghost)));
        Map<?, ?> profiles = (Map<?, ?>) loader.loadConfig().get("profiles");
        Map<?, ?> waf = (Map<?, ?>) profiles.get("auto_waf_bypass");
        Map<?, ?> options = (Map<?, ?>) waf.get("options");
        assertEquals(ghost, options.get("ghost_bits"));
    }

    @Test
    public void everyDefaultWafSwitchSurvivesSaveReloadAndRestart() {
        Map<String, Object> before = loader.loadConfig();
        Map<String, Object> profiles = map(before.get("profiles"));
        Map<String, Object> options = map(map(profiles.get("auto_waf_bypass")).get("options"));
        Map<String, Object> changed = toggleBooleans(options);
        assertTrue(loader.saveWafOptions(changed));
        ConfigLoader restarted = new ConfigLoader(temporaryFolder.getRoot().getAbsolutePath());
        Map<String, Object> restored = map(restarted.loadConfig().get("profiles"));
        assertEquals(changed, map(restored.get("auto_waf_bypass")).get("options"));
        assertEquals(profiles.get("auto_access_bypass"), restored.get("auto_access_bypass"));
        assertEquals(profiles.get("manual_waf_bypass"), restored.get("manual_waf_bypass"));
        assertTrue(restarted.saveWafOptions(options));
        assertEquals(before, restarted.loadConfig());
    }

    @Test
    public void missingNestedSectionsAndMultipleFieldsAreInsertedWithoutDuplicateKeys() throws Exception {
        Map<String, Object> defaults = map(map(map(loader.loadConfig().get("profiles"))
                .get("auto_waf_bypass")).get("options"));
        write("profiles:\n  auto_waf_bypass:\n    options:\n"
                + "      ghost_bits:\n        # keep this comment\n        generic:\n"
                + "          # missing all generic fields\n  manual_waf_bypass:\n    custom: keep\n");
        assertTrue(loader.saveWafOptions(defaults));
        assertEquals(defaults, map(map(map(loader.loadConfig().get("profiles"))
                .get("auto_waf_bypass")).get("options")));
        assertTrue(loader.readConfigText().contains("# keep this comment"));
        assertEquals("keep", map(map(loader.loadConfig().get("profiles")).get("manual_waf_bypass")).get("custom"));
        String firstSave = loader.readConfigText();
        assertTrue(loader.saveWafOptions(defaults));
        assertEquals(firstSave, loader.readConfigText());
    }

    @Test
    public void invalidPatchedYamlDoesNotReplaceTheExistingFile() throws Exception {
        String broken = "profiles:\n  auto_waf_bypass:\n    options: {body_charset: {utf_16: true}}\n";
        write(broken);
        assertFalse(loader.saveWafOptions(Collections.<String, Object>singletonMap("body_charset",
                Collections.singletonMap("utf_16", false))));
        assertEquals(broken, loader.readConfigText());
    }

    @Test
    public void invalidGeneralNumbersNeverReachDisk() {
        String before = loader.readConfigText();
        assertFalse(loader.saveGeneralConfig(5, 3, Double.NaN, "en"));
        assertFalse(loader.saveGeneralConfig(5, 3, Double.POSITIVE_INFINITY, "en"));
        assertFalse(loader.saveGeneralConfig(0, 3, 0.85, "en"));
        assertEquals(before, loader.readConfigText());
    }

    @Test
    public void invalidReloadHasAnActionableErrorAndAValidReloadClearsIt() throws Exception {
        String valid = loader.readConfigText();
        write("profiles: [broken");
        assertTrue(loader.loadConfig().isEmpty());
        assertNotNull(loader.getLastError());
        write(valid);
        assertFalse(loader.loadConfig().isEmpty());
        assertNull(loader.getLastError());
    }

    @Test
    public void emptyConfigCannotBeSilentlyReplacedByPartialSettings() throws Exception {
        write(" ");
        assertFalse(loader.saveGeneralConfig(5, 3, 0.85, "en"));
        assertFalse(loader.saveWafOptions(Collections.<String, Object>singletonMap("body_charset",
                Collections.singletonMap("utf_16", false))));
        assertEquals(" ", loader.readConfigText());
        assertNotNull(loader.getLastError());
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> map(Object value) { return (Map<String, Object>) value; }

    private Map<String, Object> toggleBooleans(Map<String, Object> values) {
        Map<String, Object> result = new LinkedHashMap<>();
        values.forEach((key, value) -> result.put(key, value instanceof Map ? toggleBooleans(map(value))
                : value instanceof Boolean ? !((Boolean) value) : value));
        return result;
    }

    private void assertGeneral(int threads, int redirects, double threshold, String lang) {
        Map<?, ?> general = (Map<?, ?>) loader.loadConfig().get("general");
        assertNotNull("Saved YAML must remain readable", general);
        assertEquals(threads, general.get("threads"));
        assertEquals(redirects, general.get("max_redirects"));
        assertEquals(threshold, general.get("similarity_threshold"));
        assertEquals(lang, general.get("lang"));
    }

    private void write(String text) throws Exception {
        Files.write(Paths.get(loader.getConfigFilePath()), text.getBytes(StandardCharsets.UTF_8));
    }
}
