package Main.ghostbits;

import org.junit.Test;
import static org.junit.Assert.*;

public class ParserPreviewTest {
    @Test public void unicodeDigitAndFullwidthUseDigitParsingRatherThanLowBits() {
        assertEquals("A", ParserPreview.evaluate("Fullwidth URL", "%４１").value);
        assertEquals("A", ParserPreview.evaluate("jdk_urldecoder_unicode_digit", "%٤1").value);
        assertNotEquals("A", GhostBitsEngine.foldToAscii("%４１"));
        assertEquals("@type", ParserPreview.evaluate("fastjson \\u", "\\u٠٠٤٠type").value);
    }
    @Test public void narrowingHexAndLooseTableHaveSeparateModels() {
        // 丰 U+4E30 -> '0'; 临 U+4E34 -> '4'; 乄 U+4E44 -> 'D'.
        assertEquals("@type", ParserPreview.evaluate("jackson \\u", "\\u丰丰临丰type").value);
        assertEquals("\u00D0type", ParserPreview.evaluate("jackson \\u", "\\u丰丰乄丰type").value);
        assertEquals("@type", ParserPreview.evaluate("fastjson \\x4_", "\\x4Jtype").value);
        assertEquals(".", ParserPreview.evaluate("Jetty %2>", "%2>").value);
        assertEquals("j", ParserPreview.evaluate("Tomcat %HH", "%鸶繡").value);
    }

}
