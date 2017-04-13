package pm.x25.osnmpd.test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

import com.sun.jna.IntegerType;
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;

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
public interface LibC extends Library {
	
	public static class SizeT extends IntegerType {

		public SizeT() {
			this(0);
		}
		
		public SizeT(final long value) {
			super(Native.SIZE_T_SIZE, value);
		}
	}
	
	public static class TimeVal extends Structure {
		public NativeLong tv_sec;
		public NativeLong tv_usec;
		
		public TimeVal(int sec, int usec) {
			super();
			this.tv_sec = new NativeLong(sec);
			this.tv_usec = new NativeLong(usec);
		}
		
		protected List<String> getFieldOrder() {
			return Arrays.asList("tv_sec", "tv_usec");
		}
	}
	
	public static class UnixSockAddress extends Structure {
		public final static int SUN_PATH_SIZE = 108;
		public short sun_family;
		public byte[] sun_path = new byte[SUN_PATH_SIZE];
		
		public UnixSockAddress(final String path) {
			this.sun_family = AF_UNIX;
			final byte[] pathEncoded = path.getBytes(StandardCharsets.UTF_8);
			System.arraycopy(pathEncoded, 0, this.sun_path, 0, pathEncoded.length);
			System.arraycopy(new byte[] {0x00}, 0, this.sun_path, pathEncoded.length, 1);
		}
		
		protected List<String> getFieldOrder() {
			return Arrays.asList("sun_family", "sun_path");
		}
	}
	
	LibC INSTANCE = (LibC)Native.loadLibrary("c", LibC.class);
	
	int AF_UNIX = 1;
	int SOCK_STREAM = 1;
	int SOL_SOCKET = 0x01;
	int SO_RCVTIMEO = 0x14;
	int SO_SNDTIMEO = 0x15;
	
	int socket(int domain, int type, int protocol);
	int setsockopt(int fd, int level, int option_name, Pointer option_value, int option_len);
	int connect(int fd, UnixSockAddress sockaddr, int length);
	int bind(int fd, UnixSockAddress sockaddr, int length);
	int listen(int sockfd, int backlog);
	int accept(int sockfd, Pointer address, SizeT addrlen);
	int recv(int fd, ByteBuffer buf, int len, int flags);
	SizeT write(final int fd, final ByteBuffer buffer, SizeT length);
	int close(final int fd);
	int umask (int mask);
	String strerror(int errno);

}
