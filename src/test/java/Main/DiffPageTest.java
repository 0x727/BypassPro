package Main;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class DiffPageTest {

    @Test
    public void compareIgnoresScriptChangesInLargeHtml() {
        String prefix = "<html><body>" + repeat('A', 9000);
        String a = prefix + "<script>" + repeat('X', 2000) + "</script></body></html>";
        String b = prefix + "<script>" + repeat('Y', 2000) + "</script></body></html>";

        assertEquals(1.0, DiffPage.getRatio(a, b, "text/html"), 0.0001);
    }

    @Test
    public void filteredPageContentRemainsBounded() {
        String html = "<html><body>" + repeat('A', 9000) + "</body></html>";

        assertTrue(DiffPage.getFilteredPageContent(html).length() <= 8000);
    }

    private static String repeat(char c, int count) {
        StringBuilder sb = new StringBuilder(count);
        for (int i = 0; i < count; i++) {
            sb.append(c);
        }
        return sb.toString();
    }
}
