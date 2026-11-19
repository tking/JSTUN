package de.javawi.jstun.header;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import de.javawi.jstun.attribute.MessageAttribute;
import de.javawi.jstun.attribute.MessageAttributeInterface.MessageAttributeType;
import de.javawi.jstun.attribute.Username;
import de.javawi.jstun.header.MessageHeaderInterface.MessageHeaderType;
import de.javawi.jstun.util.UtilityException;

public class MessageHeaderTest {

    @Test
    public void testConstructors() {
        MessageHeader mh = new MessageHeader();
        assertNull(mh.getType());

        MessageHeader mh2 = new MessageHeader(MessageHeaderType.BindingRequest);
        assertEquals(MessageHeaderType.BindingRequest, mh2.getType());
    }

    @Test
    public void testTypeHandling() {
        MessageHeader mh = new MessageHeader();
        mh.setType(MessageHeaderType.BindingResponse);
        assertEquals(MessageHeaderType.BindingResponse, mh.getType());

        assertEquals(MessageHeader.BINDINGREQUEST, MessageHeader.typeToInteger(MessageHeaderType.BindingRequest));
        assertEquals(MessageHeader.BINDINGRESPONSE, MessageHeader.typeToInteger(MessageHeaderType.BindingResponse));
        assertEquals(MessageHeader.BINDINGERRORRESPONSE,
                MessageHeader.typeToInteger(MessageHeaderType.BindingErrorResponse));
        assertEquals(MessageHeader.SHAREDSECRETREQUEST,
                MessageHeader.typeToInteger(MessageHeaderType.SharedSecretRequest));
        assertEquals(MessageHeader.SHAREDSECRETRESPONSE,
                MessageHeader.typeToInteger(MessageHeaderType.SharedSecretResponse));
        assertEquals(MessageHeader.SHAREDSECRETERRORRESPONSE,
                MessageHeader.typeToInteger(MessageHeaderType.SharedSecretErrorResponse));
        assertEquals(-1, MessageHeader.typeToInteger(null));
    }

    @Test
    public void testTransactionID() throws UtilityException {
        MessageHeader mh = new MessageHeader();
        mh.generateTransactionID();
        byte[] id = mh.getTransactionID();
        assertNotNull(id);
        assertEquals(16, id.length);

        MessageHeader mh2 = new MessageHeader();
        mh2.setTransactionID(id);
        assertArrayEquals(id, mh2.getTransactionID());
        assertTrue(mh.equalTransactionID(mh2));
        assertTrue(mh2.equalTransactionID(mh));

        MessageHeader mh3 = new MessageHeader();
        mh3.generateTransactionID();
        assertFalse(mh.equalTransactionID(mh3));
    }

    @Test
    public void testAttributes() {
        MessageHeader mh = new MessageHeader();
        Username username = new Username("testuser");
        mh.addMessageAttribute(username);

        MessageAttribute retrieved = mh.getMessageAttribute(MessageAttributeType.Username);
        assertNotNull(retrieved);
        assertEquals(username, retrieved);

        assertNull(mh.getMessageAttribute(MessageAttributeType.MappedAddress));
    }

    @Test
    public void testSerializationAndParsing() throws Exception {
        MessageHeader mh = new MessageHeader(MessageHeaderType.BindingRequest);
        mh.generateTransactionID();
        Username username = new Username("testuser");
        mh.addMessageAttribute(username);

        byte[] data = mh.getBytes();
        assertNotNull(data);
        assertTrue(data.length > 20); // Header is 20 bytes + attribute
        assertEquals(data.length, mh.getLength());

        MessageHeader parsedMh = MessageHeader.parseHeader(data);
        assertEquals(mh.getType(), parsedMh.getType());
        parsedMh.parseAttributes(data);
        assertTrue(mh.equalTransactionID(parsedMh));
        MessageAttribute parsedAttr = parsedMh.getMessageAttribute(MessageAttributeType.Username);
        assertNotNull(parsedAttr);
        assertEquals(MessageAttributeType.Username, parsedAttr.getType());
        assertTrue(parsedAttr instanceof Username);
        // Note: Username attribute might not implement equals, so we might check
        // content if needed.
        // But for now checking existence and type is good.
    }

    @Test
    public void testParseHeaderInvalid() {
        byte[] invalidData = new byte[10];
        assertThrows(Exception.class, () -> {
            MessageHeader.parseHeader(invalidData);
        });
    }

    @Test
    public void testParseAttributesIncludesExpectedAndActualLengthOnTruncation() throws Exception {
        MessageHeader shortMh = new MessageHeader(MessageHeaderType.BindingRequest);
        Exception shortEx = assertThrows(Exception.class, () -> shortMh.parseAttributes(new byte[12]));
        assertTrue(shortEx.getMessage().contains("expected at least 20 bytes"));
        assertTrue(shortEx.getMessage().contains("actual 12 bytes"));

        MessageHeader req = new MessageHeader(MessageHeaderType.BindingRequest);
        req.generateTransactionID();
        byte[] truncated = new byte[24];
        System.arraycopy(req.getBytes(), 0, truncated, 0, 20);
        // Claim 100-byte payload when only 4 bytes follow the header
        truncated[2] = 0x00;
        truncated[3] = 0x64;
        MessageHeader parsed = MessageHeader.parseHeader(truncated);
        Exception truncEx = assertThrows(Exception.class, () -> parsed.parseAttributes(truncated));
        assertTrue(truncEx.getMessage().contains("expected 120 bytes"));
        assertTrue(truncEx.getMessage().contains("actual 24 bytes"));
    }
}
