/*
 * Copyright (c) 2017, Adam <Adam@sigterm.info>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package net.runelite.injector;

import net.runelite.asm.ClassFile;
import net.runelite.asm.ClassGroup;
import net.runelite.asm.Method;
import net.runelite.asm.Type;
import net.runelite.asm.attributes.Annotations;
import net.runelite.asm.attributes.Code;
import net.runelite.asm.attributes.annotation.Annotation;
import net.runelite.asm.attributes.code.Instruction;
import net.runelite.asm.attributes.code.InstructionType;
import net.runelite.asm.attributes.code.Instructions;
import net.runelite.asm.attributes.code.instruction.types.InvokeInstruction;
import net.runelite.asm.attributes.code.instruction.types.ReturnInstruction;
import net.runelite.asm.attributes.code.instructions.*;
import net.runelite.asm.pool.Class;
import net.runelite.asm.pool.Field;
import net.runelite.asm.signature.Signature;
import net.runelite.deob.DeobAnnotations;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class InjectHookMethod
{
	public static final String HOOKS = "net/runelite/client/callback/Hooks";
	private static final Logger logger = LoggerFactory.getLogger(InjectHookMethod.class);
	private final Inject inject;

	InjectHookMethod(Inject inject)
	{
		this.inject = inject;
	}

	void process(Method method) throws InjectionException
	{
		Annotations an = method.getAnnotations();
		if (an == null)
		{
			return;
		}

//		String bypassName = "read";
//		String bypassClassName = "NetSocket";
//		if (method.getName().equals(bypassName) && method.getClassFile().getClassName().equals(bypassClassName)) {
//			inject(null, method, "readNetSocket", false, false);
//			return;
//		}
//
//		String anotherName = "finalize";
//		String anotherClassName = "AccessFile";
//		if (method.getName().equals(anotherName) && method.getClassFile().getClassName().equals(anotherClassName)) {
//			inject(null, method, "finalizeAF", false, false);
//			return;
//		}

		String clientMethName = "method1316";
		String clientClassName = "Client";
		if (method.getName().equals(clientMethName) && method.getClassFile().getClassName().equals(clientClassName)) {
			inject(null, method, "clientSP", false, false);
			return;
		}

		// Uncomment for now
//		String buffName = "read";
//		String buffClassName = "BufferedNetSocket";
//		if (method.getName().equals(buffName) && method.getClassFile().getClassName().equals(buffClassName)) {
//			inject(null, method, "bufferNS", false, false);
//			return;
//		}
//
//		String buffCons = "<init>>";
//		if (method.getName().equals(buffCons) && method.getClassFile().getClassName().equals(buffClassName)) {
//			inject(null, method, "initNS", false, false);
//			return;
//		}

		Annotation a = an.find(DeobAnnotations.HOOK);
		if (a == null)
		{
			return;
		}

		String hookName = a.getElement().getString();
		boolean end = a.getElements().size() == 2 && a.getElements().get(1).getValue().equals(true);

		inject(null, method, hookName, end, true);
	}

	public void inject(Method hookMethod, Method method, String name, boolean end, boolean useHooks) throws InjectionException
	{
		Annotations an = method.getAnnotations();

		// Method is hooked
		// Find equivalent method in vanilla, and insert callback at the beginning
		ClassFile cf = method.getClassFile();
		String obfuscatedMethodName = DeobAnnotations.getObfuscatedName(an),
			obfuscatedClassName = DeobAnnotations.getObfuscatedName(cf.getAnnotations());

		// might be a constructor
		if (obfuscatedMethodName == null)
		{
			obfuscatedMethodName = method.getName();
		}

		assert obfuscatedClassName != null : "hook on method in class with no obfuscated name";
		assert obfuscatedMethodName != null : "hook on method with no obfuscated name";

		Signature obfuscatedSignature = inject.getMethodSignature(method);

		ClassGroup vanilla = inject.getVanilla();
		ClassFile vanillaClass = vanilla.findClass(obfuscatedClassName);
		Method vanillaMethod = vanillaClass.findMethod(obfuscatedMethodName, obfuscatedSignature);
		assert method.isStatic() == vanillaMethod.isStatic();

		// Insert instructions at beginning of method
		injectHookMethod(hookMethod, name, end, method, vanillaMethod, useHooks);
	}

	private void injectHookMethod(Method hookMethod, String hookName, boolean end, Method deobMethod, Method vanillaMethod, boolean useHooks) throws InjectionException
	{
		Code code = vanillaMethod.getCode();
		if (code == null)
		{
			logger.warn(vanillaMethod + " code is null");
		}
		Instructions instructions = code.getInstructions();

		Signature.Builder builder = new Signature.Builder()
			.setReturnType(Type.VOID); // Hooks always return void

		String clientSP = "clientSP";
		for (Type type : deobMethod.getDescriptor().getArguments())
		{
			if (!hookName.equals(clientSP)) {
				builder.addArgument(inject.deobfuscatedTypeToApiType(type));
			}
		}

		assert deobMethod.isStatic() == vanillaMethod.isStatic();

		boolean modifiedSignature = false;
		if (!deobMethod.isStatic() && useHooks)
		{
			// Add variable to signature
			if (!hookName.equals(clientSP)) {
				builder.addArgument(0, inject.deobfuscatedTypeToApiType(new Type(deobMethod.getClassFile().getName())));
				modifiedSignature = true;
			}
		}

		Signature signature = builder.build();

		// Finds out *where* we should insert instructions
		String bypassNetSocket = "readNetSocket";
		String bypassAF = "finalizeAF";
		String bypassNS = "bufferNS";
		String initNS = "initNS";
//		String clientSP = "clientSP";
		if (!hookName.equals(bypassNetSocket) && !hookName.equals(bypassAF) && !hookName.equals(bypassNS) && !hookName.equals(initNS) && !hookName.equals(clientSP)) {
			List<Integer> insertIndexes = findHookLocations(hookName, end, vanillaMethod);
			insertIndexes.sort((a, b) -> Integer.compare(b, a));

			for (int insertPos : insertIndexes) {
				if (!deobMethod.isStatic()) {
					instructions.addInstruction(insertPos++, new ALoad(instructions, 0));
				}

				int signatureStart = modifiedSignature ? 1 : 0;
				int index = deobMethod.isStatic() ? 0 : 1; // current variable index

				for (int i = signatureStart; i < signature.size(); ++i) {
					Type type = signature.getTypeOfArg(i);

					Instruction load = inject.createLoadForTypeIndex(instructions, type, index);
					instructions.addInstruction(insertPos++, load);

					index += type.getSize();
				}

				InvokeInstruction invoke;

				// use old Hooks callback
				if (useHooks) {
					// Invoke callback
					invoke = new InvokeStatic(instructions,
							new net.runelite.asm.pool.Method(
									new net.runelite.asm.pool.Class(HOOKS),
									hookName,
									signature
							)
					);
				} else {
					// Invoke methodhook
					assert hookMethod != null;

					if (vanillaMethod.isStatic()) {
						invoke = new InvokeStatic(instructions,
								new net.runelite.asm.pool.Method(
										new net.runelite.asm.pool.Class("client"), // Static methods are in client
										hookMethod.getName(),
										signature
								)
						);
					} else {
						// otherwise invoke member function
						//instructions.addInstruction(insertPos++, new ALoad(instructions, 0));
						invoke = new InvokeVirtual(instructions,
								new net.runelite.asm.pool.Method(
										new net.runelite.asm.pool.Class(vanillaMethod.getClassFile().getName()),
										hookMethod.getName(),
										hookMethod.getDescriptor()
								)
						);
					}
				}

				instructions.addInstruction(insertPos++, (Instruction) invoke);
			}
		}

		int index1 = -1;
		int index2 = -1;
		if (hookName.equals("removeFriend")) {
			// This changes the packet to ClientPacket.field2224
//			Instruction newIns = new GetStatic(instructions, new Field(new Class("gj"), "s", new Type("Lgj;")));

			// ClientPacket.field2301
//			Instruction newIns = new GetStatic(instructions, new Field(new Class("gj"), "co", new Type("Lgj;")));

			// ClientPacket.field2295
//			Instruction newIns = new GetStatic(instructions, new Field(new Class("gj"), "bh", new Type("Lgj;")));

			// ClientPacket.field2225
			Instruction newIns = new GetStatic(instructions, new Field(new Class("gj"), "cn", new Type("Lgj;")));
			Instruction replace = null;

			for (Instruction i : instructions.getInstructions()) {
				// Replace ClientPacket used.
				if (i.toString().equals("getstatic static Lgj; gj.cs in bz.t(Ljava/lang/String;I)V")) {
					logger.info("instruction {}", i);
					replace = i;
				}

				// Replace writeByte with writeShort
				if (i.toString().equals("invokevirtual kj.an(II)V in bz.t(Ljava/lang/String;I)V")) {
					index1 = instructions.getInstructions().indexOf(i);
				}

				// Lets us find the GOTO statement that gets to AddNode
				if (i.toString().equals("invokevirtual kj.bo(Ljava/lang/String;I)V in bz.t(Ljava/lang/String;I)V")) {
					index2 = instructions.getInstructions().indexOf(i);
				}
			}

			assert replace != null;
			assert index1 != -1;
			assert index2 != -1;

			// Refreshes the bytecode before printing.
			newIns.lookup();

			logger.info("replace ins {}", newIns);

			// Replace the old ClientPacket variable.
			instructions.replace(replace, newIns);

			// Replace Instruction at index1 - 4
			Instruction replaceOne = instructions.getInstructions().get(index1 - 4);
			Instruction newBipush = new BiPush(instructions, Byte.parseByte("100"));
			newBipush.lookup();
			instructions.replace(replaceOne, newBipush);

			// If we put another item on the stack, this will all compile, but then the method is entirely pointless.
			// Is it necessary to have a BIPUSH here?
			Instruction replaceTwo = instructions.getInstructions().get(index1 - 3);
//			Instruction anotherBipush = new BiPush(instructions, Byte.parseByte("127"));
//			Instruction anotherBipush = new LDC(instructions, 56);
			Instruction anotherBipush = new LDC(instructions, -8);
			anotherBipush.lookup();
			instructions.replace(replaceTwo, anotherBipush);

			// Replace Instruction at index1 - 2
			Instruction replaceThree = instructions.getInstructions().get(index1 - 2);
			//Instruction newWrite = new InvokeVirtual(instructions, new net.runelite.asm.pool.Method(new Class("kj"), "al", new Signature("(IB)V")));
//			Instruction newWrite = new InvokeVirtual(instructions, new net.runelite.asm.pool.Method(new Class("kj"), "ax", new Signature("(IB)V")));
			Instruction newWrite = new InvokeVirtual(instructions, new net.runelite.asm.pool.Method(new Class("kj"), "ca", new Signature("(IB)V")));
			newWrite.lookup();
			instructions.replace(replaceThree, newWrite);

			// Replace Instruction at index1 - 1 with GOTO instruction to addNode().
			Instruction replaceFour = instructions.getInstructions().get(index1 - 1);
			Instruction gotoInstruction = instructions.getInstructions().get(index2 + 1);
			Instruction gotoClone = gotoInstruction.clone();
			gotoClone.lookup();
			instructions.replace(replaceFour, gotoClone);

			// Remove index1, index1 + 1 here.
			instructions.getInstructions().remove(index1);
			instructions.getInstructions().remove(index1);

			// Add the other instructions at index1 - 1 so that the GOTO is shifted after these instructions.
			// Copy the ALOAD of PacketBufferNode
			Instruction aloadPBN = instructions.getInstructions().get(index1 - 6);
			Instruction aloadClone = aloadPBN.clone();
			aloadClone.lookup();
			instructions.addInstruction(index1 - 1, aloadClone);

			// Copy the GETFIELD of packetBuffer
			Instruction getfieldPB = instructions.getInstructions().get(index1 - 5);
			Instruction getfieldClone = getfieldPB.clone();
			getfieldClone.lookup();
			instructions.addInstruction(index1, getfieldClone);

			// BIPUSH
			Instruction thirdBipush = new BiPush(instructions, Byte.parseByte("2"));
			thirdBipush.lookup();
			instructions.addInstruction(index1 + 1, thirdBipush);

			// Another BIPUSH
//			Instruction fourthBipush = new BiPush(instructions, Byte.parseByte("127"));
//			Instruction fourthBipush = new LDC(instructions, -1);
			Instruction fourthBipush = new LDC(instructions, 2035333434);
			fourthBipush.lookup();
			instructions.addInstruction(index1 + 2, fourthBipush);

			// kj.al InvokeVirtual
//			Instruction writeShortClone = newWrite.clone();
//			Instruction writeShortClone = new InvokeVirtual(instructions, new net.runelite.asm.pool.Method(new Class("kj"), "al", new Signature("(IB)V")));
			Instruction writeShortClone = new InvokeVirtual(instructions, new net.runelite.asm.pool.Method(new Class("kj"), "dc", new Signature("(II)V")));
			writeShortClone.lookup();
			instructions.addInstruction(index1 + 3, writeShortClone);

			// One more ALOAD
			Instruction aloadClone2 = aloadPBN.clone();
			aloadClone2.lookup();
			instructions.addInstruction(index1 + 4, aloadClone2);

			// One more GETFIELD
			Instruction getfieldClone2 = getfieldPB.clone();
			getfieldClone2.lookup();
			instructions.addInstruction(index1 + 5, getfieldClone2);

			// Two BIPUSH
			Instruction fifthBipush = new BiPush(instructions, Byte.parseByte("1"));
			fifthBipush.lookup();
			instructions.addInstruction(index1 + 6, fifthBipush);

//			Instruction sixthBipush = new BiPush(instructions, Byte.parseByte("1"));
//			Instruction sixthBipush = new LDC(instructions, 23275811);
			Instruction sixthBipush = new LDC(instructions, -1379722724);
			sixthBipush.lookup();
			instructions.addInstruction(index1 + 7, sixthBipush);

			// kj.al InvokeVirtual
//			Instruction writeShortClone2 = newWrite.clone();
//			Instruction writeShortClone2 = new InvokeVirtual(instructions, new net.runelite.asm.pool.Method(new Class("kj"), "cf", new Signature("(II)V")));
			Instruction writeShortClone2 = new InvokeVirtual(instructions, new net.runelite.asm.pool.Method(new Class("kj"), "cn", new Signature("(II)V")));
			writeShortClone2.lookup();
			instructions.addInstruction(index1 + 8, writeShortClone2);

			// Extra, method5811
			Instruction aloadClone3 = aloadPBN.clone();
			aloadClone3.lookup();
			instructions.addInstruction(index1 + 9, aloadClone3);

			Instruction getfieldClone3 = getfieldPB.clone();
			getfieldClone3.lookup();
			instructions.addInstruction(index1 + 10, getfieldClone3);

			Instruction sevBipush = new BiPush(instructions, Byte.parseByte("1"));
			sevBipush.lookup();
			instructions.addInstruction(index1 + 11, sevBipush);

//			Instruction eigBipush = new BiPush(instructions, Byte.parseByte("1"));
//			Instruction eigBipush = new LDC(instructions, 2035333434);
			Instruction eigBipush = new LDC(instructions, -8);
			eigBipush.lookup();
			instructions.addInstruction(index1 + 12, eigBipush);

//			Instruction method5811 = new InvokeVirtual(instructions, new net.runelite.asm.pool.Method(new Class("kj"), "dc", new Signature("(II)V")));
			Instruction method5811 = new InvokeVirtual(instructions, new net.runelite.asm.pool.Method(new Class("kj"), "ca", new Signature("(IB)V")));
			method5811.lookup();
			instructions.addInstruction(index1 + 13, method5811);

			Signature.Builder builderPnt = new Signature.Builder().addArgument(Type.INT).setReturnType(Type.VOID);
			Instruction getstat = new GetStatic(instructions, new Field(new Class("java/lang/System"), "out", new Type("Ljava/io/PrintStream;")));
			Instruction bipPrint = new BiPush(instructions, Byte.parseByte("9"));
			Instruction pnt = new InvokeVirtual(instructions, new net.runelite.asm.pool.Method(new Class("java/io/PrintStream"), "println", new Signature(builderPnt.build())));
			getstat.lookup();
			bipPrint.lookup();
			pnt.lookup();
			instructions.addInstruction(index1 + 14, getstat);
			instructions.addInstruction(index1 + 15, bipPrint);
			instructions.addInstruction(index1 + 16, pnt);


			// Extra, writeShort
//			Instruction aloadClone4 = aloadPBN.clone();
//			aloadClone4.lookup();
//			instructions.addInstruction(index1 + 14, aloadClone4);
//
//			Instruction getfieldClone4 = getfieldPB.clone();
//			getfieldClone4.lookup();
//			instructions.addInstruction(index1 + 15, getfieldClone4);
//
//			Instruction ninBipush = new BiPush(instructions, Byte.parseByte("2"));
//			ninBipush.lookup();
//			instructions.addInstruction(index1 + 16, ninBipush);
//
////			Instruction tenBipush = new BiPush(instructions, Byte.parseByte("1"));
//			Instruction tenBipush = new LDC(instructions, -1);
//			tenBipush.lookup();
//			instructions.addInstruction(index1 + 17, tenBipush);
//
//			Instruction wsClone = new InvokeVirtual(instructions, new net.runelite.asm.pool.Method(new Class("kj"), "al", new Signature("(IB)V")));
//			wsClone.lookup();
//			instructions.addInstruction(index1 + 18, wsClone);
//
//			// Final, method5636
//			Instruction aloadClone5 = aloadPBN.clone();
//			aloadClone5.lookup();
//			instructions.addInstruction(index1 + 19, aloadClone5);
//
//			Instruction getfieldClone5 = getfieldPB.clone();
//			getfieldClone5.lookup();
//			instructions.addInstruction(index1 + 20, getfieldClone5);
//
//			Instruction eleBipush = new BiPush(instructions, Byte.parseByte("1"));
//			eleBipush.lookup();
//			instructions.addInstruction(index1 + 21, eleBipush);
//
////			Instruction tweBipush = new BiPush(instructions, Byte.parseByte("1"));
//			Instruction tweBipush = new LDC(instructions, 1799174836);
//			tweBipush.lookup();
//			instructions.addInstruction(index1 + 22, tweBipush);
//
//			Instruction method5636 = new InvokeVirtual(instructions, new net.runelite.asm.pool.Method(new Class("kj"), "ce", new Signature("(II)V")));
//			method5636.lookup();
//			instructions.addInstruction(index1 + 23, method5636);

			logger.info("Injected method hook {} in {} with {} args: {}, ins: {}",
				hookName, vanillaMethod, signature.size(),
				signature.getArguments(), instructions.getInstructions());
		}

		if (hookName.equals(bypassNetSocket)) {
			// Want to set up some logging here :)
			Signature.Builder builderPnt = new Signature.Builder().addArgument(Type.INT).setReturnType(Type.VOID);

			Instruction getstat = new GetStatic(instructions, new Field(new Class("java/lang/System"), "out", new Type("Ljava/io/PrintStream;")));
			Instruction bipPrint = new BiPush(instructions, Byte.parseByte("9"));
			Instruction pnt = new InvokeVirtual(instructions, new net.runelite.asm.pool.Method(new Class("java/io/PrintStream"), "println", new Signature(builderPnt.build())));

			getstat.lookup();
			bipPrint.lookup();
			pnt.lookup();

			instructions.addInstruction(1, getstat);
			instructions.addInstruction(2, bipPrint);
			instructions.addInstruction(3, pnt);

			logger.info("Injected method hook {} in {} with {} args: {}, ins: {}",
					hookName, vanillaMethod, signature.size(),
					signature.getArguments(), instructions.getInstructions());
		}

		if (hookName.equals(bypassNS)) {
			Signature.Builder builderPnt = new Signature.Builder().addArgument(Type.INT).setReturnType(Type.VOID);

			// Arrays.toString(byteArray) instead of the decimal value..
			Instruction aloadBuffer = instructions.getInstructions().get(6).clone();

			Instruction getstat = new GetStatic(instructions, new Field(new Class("java/lang/System"), "out", new Type("Ljava/io/PrintStream;")));
			Instruction bipPrint = new BiPush(instructions, Byte.parseByte("9"));
			Instruction pnt = new InvokeVirtual(instructions, new net.runelite.asm.pool.Method(new Class("java/io/PrintStream"), "println", new Signature(builderPnt.build())));

			getstat.lookup();
			bipPrint.lookup();
			pnt.lookup();

			instructions.addInstruction(1, getstat);
			instructions.addInstruction(2, bipPrint);
			instructions.addInstruction(3, pnt);

			// Try to print the buffer that the BufferedSource uses.
			instructions.replace(bipPrint, aloadBuffer);

			logger.info("Injected method hook {} in {} with {} args: {}, ins: {}",
					hookName, vanillaMethod, signature.size(),
					signature.getArguments(), instructions.getInstructions());
		}

		if (hookName.equals(initNS)) {
			// Change socket timeout
			// Change sipush 30000 to ldc 90000
			// Turns out there must be another timeout somewhere, so this one doesn't matter....
			Instruction newIns = new LDC(instructions, 90000);
			Instruction replace = null;

			for (Instruction i : instructions.getInstructions()) {
				// Replace sipush
				if (i.toString().equals("sipush 30000")) {
					replace = i;
				}
			}

			assert replace != null;

			newIns.lookup();
			instructions.replace(replace, newIns);

			logger.info("Injected method hook {} in {} with {} args: {}, ins: {}",
					hookName, vanillaMethod, signature.size(),
					signature.getArguments(), instructions.getInstructions());
		}

		if (hookName.equals(clientSP)) {
			Instruction replace = null;

			for (Instruction i : instructions.getInstructions()) {
//				if (i.toString().equals("net.runelite.asm.attributes.code.instructions.ALoad@3d72e40d in client.hc(Lcc;I)Z")) {
				if (i.toString().equals("net.runelite.asm.attributes.code.instructions.ALoad@3837cd45 in client.hc(Lcc;I)Z")) {
					replace = i;
				}
			}

			assert replace != null;

			int index = instructions.getInstructions().indexOf(replace);
//			Instruction ldc = instructions.getInstructions().get(index + 3);
//			Instruction newldc = new LDC(instructions, 0);
//			instructions.replace(ldc, newldc);

			Signature.Builder builderPnt = new Signature.Builder().addArgument(Type.INT).setReturnType(Type.VOID);

			Instruction getstat = new GetStatic(instructions, new Field(new Class("java/lang/System"), "out", new Type("Ljava/io/PrintStream;")));

			Instruction aloadcopy = replace.clone();
			Instruction getfield = instructions.getInstructions().get(index+1).clone();

			Instruction pnt = new InvokeVirtual(instructions, new net.runelite.asm.pool.Method(new Class("java/io/PrintStream"), "println", new Signature(builderPnt.build())));

//			int index = instructions.getInstructions().indexOf(replace);
//			Instruction rep = instructions.getInstructions().get(index - 2);
//			Instruction newldc = new LDC(instructions, 0);
//			instructions.replace(rep, newldc);

			instructions.addInstruction(index-2, getstat);
			instructions.addInstruction(index-1, aloadcopy);
			instructions.addInstruction(index, getfield);
			instructions.addInstruction(index+1, pnt);

			// Try to log the serverPacket?
			logger.info("Injected method hook {} in {} with  ins {}",
					hookName, vanillaMethod, instructions.getInstructions());
		}

		if (hookName.equals(bypassAF)) {
			// Steal logging from here :)

			logger.info("Injected method hook {} in {} with {} args: {}, ins: {}",
					hookName, vanillaMethod, signature.size(),
					signature.getArguments(), instructions.getInstructions());
		}

//		logger.info("Injected method hook {} in {} with {} args: {}",
//			hookName, vanillaMethod, signature.size(),
//			signature.getArguments());
	}

	private List<Integer> findHookLocations(String hookName, boolean end, Method vanillaMethod) throws InjectionException
	{
		Instructions instructions = vanillaMethod.getCode().getInstructions();

		if (end)
		{
			// find return
			List<Instruction> returns = instructions.getInstructions().stream()
				.filter(i -> i instanceof ReturnInstruction)
				.collect(Collectors.toList());
			List<Integer> indexes = new ArrayList<>();

			for (Instruction ret : returns)
			{
				int idx = instructions.getInstructions().indexOf(ret);
				assert idx != -1;
				indexes.add(idx);
			}

			return indexes;
		}

		if (!vanillaMethod.getName().equals("<init>"))
		{
			return Arrays.asList(0);
		}

		// Find index after invokespecial
		for (int i = 0; i < instructions.getInstructions().size(); ++i)
		{
			Instruction in = instructions.getInstructions().get(i);

			if (in.getType() == InstructionType.INVOKESPECIAL)
			{
				return Arrays.asList(i + 1); // one after
			}
		}

		throw new IllegalStateException("constructor with no invokespecial");
	}
}
