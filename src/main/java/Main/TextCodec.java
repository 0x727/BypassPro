package Main;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.*;

/** Explicit text conversion; raw bytes must never pass through a lossy encoder. */
public final class TextCodec {
    private TextCodec() {}

    public static String decode(byte[] bytes, Charset charset) throws CharacterCodingException {
        return charset.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
    }

    public static byte[] encode(String text, Charset charset) throws CharacterCodingException {
        ByteBuffer buffer = charset.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(text));
        byte[] bytes = new byte[buffer.remaining()];
        buffer.get(bytes);
        return bytes;
    }
}
