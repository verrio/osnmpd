package pm.x25.osnmpd.test;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.sun.jna.Native;

import pm.x25.osnmpd.test.LibC.SizeT;
import pm.x25.osnmpd.test.LibC.TimeVal;
import pm.x25.osnmpd.test.LibC.UnixSockAddress;
import sun.security.util.DerInputStream;
import sun.security.util.DerOutputStream;
import sun.security.util.DerValue;
import sun.security.util.ObjectIdentifier;

/**
 * This file is part of the osnmpd project (https://github.com/verrio/osnmpd).
 * Copyright (C) 2016 Olivier Verriest
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
public final class TestSubAgent implements Runnable {

	private static final Logger logger = Logger.getLogger(TestSubAgent.class.getName());

	private static final List<ObjectIdentifier> TEST_OID;
	private static final List<DerValue> TEST_VALUES;
	
	private static final int COMMAND_GET = 0xC0;
	private static final int COMMAND_GET_NEXT = 0xC1;
	private static final int COMMAND_SET = 0xC2;
	
	private static final byte NO_SUCH_OBJECT = (byte) 0x80;
	private static final byte NO_SUCH_INSTANCE = (byte) 0x81;
	private static final byte END_OF_MIB_VIEW = (byte) 0x82;
	
	private static final int RESULT_NO_ERROR = 0;
	private static final int RESULT_GENERAL_ERROR = 5;
	private static final int RESULT_NO_ACCESS = 6;

	private static final TimeVal INACTIVITY_TIMEOUT;
	private static final String SOCKET_PATH = "/var/run/snmp/java-subagent";

	static {
		try {
			TEST_OID = Arrays.asList(
				new ObjectIdentifier(new int[] { 1,3,6,1,3,867,5309,1,2,0 }),
				new ObjectIdentifier(new int[] { 1,3,6,1,3,867,5309,1,5,0 }),
				new ObjectIdentifier(new int[] { 1,3,6,1,3,867,5309,1,13,5,7,0 })
			);
			TEST_VALUES = Arrays.asList(
				new DerValue(DerValue.tag_Integer, new byte[] {0x00, (byte) 0xaa, (byte) 0xbb}),
				new DerValue(DerValue.tag_OctetString, new byte[] {1,2,3,4,5,6}),
				new DerValue(DerValue.tag_OctetString, new byte[] {1,1,1})
			);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
		
		INACTIVITY_TIMEOUT = new TimeVal(10, 0);
		INACTIVITY_TIMEOUT.write();
	}
	
	private int fd;

	public static void main(String[] args) throws Exception {
		logger.info("starting sub agent");
		new TestSubAgent().run();
		logger.info("sub agent finished");
	}

	/**
	 * {@inheritDoc}
	 */
	public final void run() {
		try {
			this.init();

			while (!Thread.currentThread().isInterrupted()) {
				final int clientSocket = LibC.INSTANCE.accept(this.fd, null, null);
				if (clientSocket == -1) {
					logger.log(Level.WARNING, "failed to accept new client connection : "
							+ LibC.INSTANCE.strerror(Native.getLastError()));
					break;
				}
				
				if (LibC.INSTANCE.setsockopt(clientSocket, LibC.SOL_SOCKET, LibC.SO_SNDTIMEO,
						INACTIVITY_TIMEOUT.getPointer(), INACTIVITY_TIMEOUT.size()) == -1
						|| LibC.INSTANCE.setsockopt(clientSocket, LibC.SOL_SOCKET, LibC.SO_RCVTIMEO,
						INACTIVITY_TIMEOUT.getPointer(), INACTIVITY_TIMEOUT.size()) == -1) {
					logger.log(Level.WARNING,"failed to set socket timeout values : "
								+ LibC.INSTANCE.strerror(Native.getLastError()));
					LibC.INSTANCE.close(clientSocket);
					continue;
				}

				this.handleRequest(clientSocket);
			}
		} catch (Exception e) {
			logger.log(Level.SEVERE, "sub agent failed : " + e.getMessage(), e);
		} finally {
			if (this.fd != -1) {
				LibC.INSTANCE.close(this.fd);
			}
		}
	}

	private final void init() throws IOException {
		this.fd = LibC.INSTANCE.socket(LibC.AF_UNIX, LibC.SOCK_STREAM, 0);
		if (this.fd == -1) {
			throw new IllegalStateException("failed to initialize agent socket  : "
					+ LibC.INSTANCE.strerror(Native.getLastError()));
		}

		final Path sockPath = Paths.get(SOCKET_PATH);
		Files.deleteIfExists(sockPath);

		final int oldMask = LibC.INSTANCE.umask(0);
		final UnixSockAddress address = new UnixSockAddress(SOCKET_PATH);

		if (LibC.INSTANCE.bind(this.fd, address, address.size()) == -1) {
			throw new IllegalStateException("failed to bind socket : "
					+ LibC.INSTANCE.strerror(Native.getLastError()));
		}
		LibC.INSTANCE.umask(oldMask);

		if (LibC.INSTANCE.listen(this.fd, 8) == -1) {
			throw new IllegalStateException("failed to initialize agent socket : "
					+ LibC.INSTANCE.strerror(Native.getLastError()));
		}
	}

	private final void handleRequest(final int clientSocket) throws IOException {
		try {
			final byte[] request = new byte[2048];
			final ByteBuffer buffer = ByteBuffer.wrap(request, 0, request.length);
			final int received = LibC.INSTANCE.recv(clientSocket, buffer, request.length, 0);
			if (received == -1) {
				throw new RuntimeException("failed to receive request from daemon : "
						+ LibC.INSTANCE.strerror(Native.getLastError()));
			} else if (received == 0) {
				throw new RuntimeException("failed to receive data from SNMP agent");
			}

			logger.info("received request");
			final ByteBuffer response = ByteBuffer.wrap(this.generateResponse(request));
			final SizeT length = new SizeT(response.remaining());
			while (length.intValue() > 0) {
				SizeT written = LibC.INSTANCE.write(clientSocket, response, length);
				if (written.intValue() == -1) {
					logger.warning("failed to send query response : "
							+ LibC.INSTANCE.strerror(Native.getLastError()));
					break;
				} else if (written.intValue() == 0) {
					logger.warning("timeout while sending query response");
					break;
				} else {
					response.position(response.position() + written.intValue());
					length.setValue(response.remaining());
				}
			}
		} finally {
			LibC.INSTANCE.close(clientSocket);
		}
	}

	private final byte[] generateResponse(final byte[] request) throws IOException {
		final DerInputStream in = new DerInputStream(request);
		final DerValue[] values = in.getSequence(5);
		
		final DerValue command = values[3];
		if (command.tag != DerValue.tag_Enumerated) {
			throw new RuntimeException("command has invalid BER tag");
		}
		
		final DerInputStream args = values[4].toDerInputStream();
		final ObjectIdentifier oid = args.getOID();
		final DerValue val = args.getDerValue();
		
		int result = 0;
		ObjectIdentifier result_oid = null;
		DerValue result_val = null;
		
		switch (command.getEnumerated()) {
			case COMMAND_GET: {
				result = RESULT_NO_ERROR;
				boolean found = false;
				for (int i = 0; i < TEST_OID.size(); i++) {
					if (TEST_OID.get(i).equals(oid)) {
						result_oid = oid;
						result_val = TEST_VALUES.get(i);
						found = true;
						break;
					}
				}
				if (!found) {
					result_oid = oid;
					result_val = new DerValue(NO_SUCH_OBJECT, new byte[0]);
				}
				break;
			}

			case COMMAND_GET_NEXT: {
				result = RESULT_NO_ERROR;
				boolean found = false;
				for (int i = 0; i < TEST_OID.size(); i++) {
					if (precedes(oid, TEST_OID.get(i))) {
						result_oid = TEST_OID.get(i);
						result_val = TEST_VALUES.get(i);
						found = true;
						break;
					}
				}
				if (!found) {
					result_oid = oid;
					result_val = new DerValue(END_OF_MIB_VIEW, new byte[0]);
				}
				break;
			}

			case COMMAND_SET: {
				result = RESULT_NO_ACCESS;
				result_oid = oid;
				result_val = val;
				break;
			}
		    
			default: {
				result = RESULT_GENERAL_ERROR;
				result_oid = oid;
				result_val = val;
			}
	    }
	    
		final DerOutputStream argStream = new DerOutputStream();
		argStream.putOID(result_oid);
		argStream.putDerValue(result_val);
		
		final DerOutputStream messageStream = new DerOutputStream();
		messageStream.putInteger(0);
		messageStream.putBitString(new byte[] {0});
		messageStream.putInteger(0);
		messageStream.putEnumerated(result);
		messageStream.write(DerValue.tag_Sequence, argStream);

		final DerOutputStream out = new DerOutputStream();
		out.write(DerValue.tag_Sequence, messageStream);
		return out.toByteArray();
	}

	private static final boolean precedes(final ObjectIdentifier oid1, final ObjectIdentifier oid2) {
		try {
			final Method method = oid1.getClass().getDeclaredMethod("toIntArray");
			method.setAccessible(true);
			int[] array1 = (int[]) method.invoke(oid1);
			int[] array2 = (int[]) method.invoke(oid2);
			
			for (int i = 0; i < Integer.min(array1.length, array2.length); i++) {
				if (array1[i] < array2[i]) {
					return true;
				} else if (array1[i] > array2[i]) {
					return false;
				}
			}
			
			return (array1.length < array2.length);
		} catch (NoSuchMethodException | SecurityException |
				IllegalAccessException | InvocationTargetException e) {
			throw new IllegalStateException(e);
		}
	}
	
}
