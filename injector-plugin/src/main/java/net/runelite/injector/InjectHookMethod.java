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
import net.runelite.asm.attributes.code.Label;
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

		String clientMethName = "doCycleLoggedIn";
		String clientClassName = "Client";
		if (method.getName().equals(clientMethName) && method.getClassFile().getClassName().equals(clientClassName)) {
			inject(null, method, "clientSP", false, false);
			return;
		}

		String cthreeMethod = "menuAction";
		String cthree = "class32";

		if (method.getName().equals(cthreeMethod) && method.getClassFile().getClassName().equals(cthree)) {
			inject(null, method, "cthree", false, false);
			return;
		}

		String wmap = "WorldMapData_1";
		String wMethod = "widgetDefaultMenuAction";
		if (method.getName().equals(wMethod) && method.getClassFile().getClassName().equals(wmap)) {
			inject(null, method, "wmap", false, false);
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
		String cthree = "cthree";
		String wmap = "wmap";
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
		if (!hookName.equals(bypassNetSocket) && !hookName.equals(bypassAF) && !hookName.equals(bypassNS) && !hookName.equals(initNS) && !hookName.equals(clientSP) && !hookName.equals(cthree) && !hookName.equals(wmap)) {
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
		int index3 = -1;
		int index4 = -1;
		int index5 = -1;
		if (hookName.equals("removeFriend")) {
			// This changes the packet to ClientPacket.field2224
//			Instruction newIns = new GetStatic(instructions, new Field(new Class("gj"), "s", new Type("Lgj;")));

			// ClientPacket.field2301
//			Instruction newIns = new GetStatic(instructions, new Field(new Class("gj"), "co", new Type("Lgj;")));

			// ClientPacket.field2295
//			Instruction newIns = new GetStatic(instructions, new Field(new Class("gj"), "bh", new Type("Lgj;")));

			// ClientPacket.field2225
//			Instruction newIns = new GetStatic(instructions, new Field(new Class("gj"), "cn", new Type("Lgj;")));

			// field2271
//			Instruction newIns = new GetStatic(instructions, new Field(new Class("gj"), "y", new Type("Lgj;")));

			// field2299 (IMPORTANT ONE)
//			Instruction newIns = new GetStatic(instructions, new Field(new Class("gj"), "b", new Type("Lgj;")));

			// GE one
//			Instruction newIns = new GetStatic(instructions, new Field(new Class("gj"), "i", new Type("Lgj;")));

			// Bank one field2313
//			Instruction newIns = new GetStatic(instructions, new Field(new Class("gj"), "w", new Type("Lgj;")));

			// BA one (seems like horn is *delayed* one chat per tick)
//			Instruction newIns = new GetStatic(instructions, new Field(new Class("gj"), "p", new Type("Lgj;")));

			//field2226
			Instruction newIns = new GetStatic(instructions, new Field(new Class("gj"), "i", new Type("Lgj;")));

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

				// goto after addNode
				if (i.toString().equals("invokevirtual cc.b(Lgx;B)V in bz.t(Ljava/lang/String;I)V")) {
					index3 = instructions.getInstructions().indexOf(i);
				}

				// first goto where we'll set some shit
//				if (i.toString().equals("label getstatic static I client.nl in bz.t(Ljava/lang/String;I)V on line number 182")) {
//					index4 = instructions.getInstructions().indexOf(i);
//				}
			}

			//1
			//22020096
			//3
			//2554

			//1
			//21954585
			//0
			//2554

			assert replace != null;
			assert index1 != -1;
			assert index2 != -1;
			assert index3 != -1;
//			assert index4 != -1;
//			assert index5 != -1;

			// Refreshes the bytecode before printing.
			newIns.lookup();

			logger.info("replace ins {}", newIns);

			// Replace the old ClientPacket variable.
			instructions.replace(replace, newIns);

			//35
			//
			//10526  -- 3
			//4      -- 0
			//9764864 - 1

			// GOTO to repeat the process
//			Label gotolabel = (Label) instructions.getInstructions().get(index1 - 7);
			Label gotolabel = instructions.createLabelFor(newIns);
			Instruction a = new Goto(instructions, gotolabel);
			instructions.addInstruction(index3+1, a);

			Instruction ret = new VReturn(instructions);
			instructions.addInstruction(index3+1, ret);

			Instruction iload = new ILoad(instructions, 10);
			Instruction addOneLDC = new LDC(instructions, 1);
			Instruction addOne = new IAdd(instructions);
			Instruction istoreagain = new IStore(instructions, 10);
			Instruction iloadagain = new ILoad(instructions, 10);
			Instruction limit = new LDC(instructions, 1000);
			Instruction cmp = new IfICmpNe(instructions, instructions.createLabelFor(a));
			instructions.addInstruction(index3+1, iload);
			instructions.addInstruction(index3+2, addOneLDC);
			instructions.addInstruction(index3+3, addOne);
			instructions.addInstruction(index3+4, istoreagain);
			instructions.addInstruction(index3+5, iloadagain);
			instructions.addInstruction(index3+6, limit);
			instructions.addInstruction(index3+7, cmp);

			//35 30

//			Instruction ldcStore = new LDC(instructions, 0);
//			Instruction istore = new IStore(instructions, 10);
//			instructions.addInstruction(index4+1, ldcStore);
//			instructions.addInstruction(index4+2, istore);

			// 31588464, -1, -1 for saving preset
			// 31588421, -1, -1 for helm cancel


			// Replace Instruction at index1 - 4
			Instruction replaceOne = instructions.getInstructions().get(index1 - 4);
			Instruction newLDC = new LDC(instructions, 2393); //
			newLDC.lookup();
			instructions.replace(replaceOne, newLDC);

			Instruction replaceTwo = instructions.getInstructions().get(index1 - 3);
			Instruction anotherBipush = new LDC(instructions, 23275811);
			anotherBipush.lookup();
			instructions.replace(replaceTwo, anotherBipush);

			// Replace Instruction at index1 - 2
			Instruction replaceThree = instructions.getInstructions().get(index1 - 2);
			Instruction newWrite = new InvokeVirtual(instructions, new net.runelite.asm.pool.Method(new Class("kj"), "cf", new Signature("(II)V")));
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
			Instruction thirdBipush = new LDC(instructions, 76); // new BiPush(instructions, Byte.parseByte("0"));
			thirdBipush.lookup();
			instructions.addInstruction(index1 + 1, thirdBipush);

			Instruction fourthBipush = new LDC(instructions, 23275811);
			fourthBipush.lookup();
			instructions.addInstruction(index1 + 2, fourthBipush);

			// kj.al InvokeVirtual
			Instruction writeShortClone = new InvokeVirtual(instructions, new net.runelite.asm.pool.Method(new Class("kj"), "cf", new Signature("(II)V")));
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
			Instruction fifthBipush = new LDC(instructions, 1);// new BiPush(instructions, Byte.parseByte("4"));
			fifthBipush.lookup();
			instructions.addInstruction(index1 + 6, fifthBipush);

			Instruction sixthBipush = new LDC(instructions, 2047890611);
			sixthBipush.lookup();
			instructions.addInstruction(index1 + 7, sixthBipush);

			// kj.al InvokeVirtual
			Instruction writeShortClone2 = new InvokeVirtual(instructions, new net.runelite.asm.pool.Method(new Class("kj"), "cy", new Signature("(II)V")));
			writeShortClone2.lookup();
			instructions.addInstruction(index1 + 8, writeShortClone2);

			Instruction aloadClone3 = aloadPBN.clone();
			aloadClone3.lookup();
			instructions.addInstruction(index1 + 9, aloadClone3);

			// One more GETFIELD
			Instruction getfieldClone3 = getfieldPB.clone();
			getfieldClone3.lookup();
			instructions.addInstruction(index1 + 10, getfieldClone3);

			// Two BIPUSH
			Instruction nBipush = new LDC(instructions, 48);// new BiPush(instructions, Byte.parseByte("4"));
			nBipush.lookup();
			instructions.addInstruction(index1 + 11, nBipush);

			Instruction niBipush = new LDC(instructions, 23275811);
			niBipush.lookup();
			instructions.addInstruction(index1 + 12, niBipush);

			// kj.al InvokeVirtual
			Instruction writeShortClone3 = new InvokeVirtual(instructions, new net.runelite.asm.pool.Method(new Class("kj"), "cf", new Signature("(II)V")));
			writeShortClone3.lookup();
			instructions.addInstruction(index1 + 13, writeShortClone3);

			for (Instruction i : instructions.getInstructions()) {
				if (i.toString().equals("label getstatic static I client.nl in bz.t(Ljava/lang/String;I)V on line number 182")) {
					index4 = instructions.getInstructions().indexOf(i);
				}
			}

			assert index4 != -1;

			Instruction ldcStore = new LDC(instructions, 0);
			Instruction istore = new IStore(instructions, 10);
			instructions.addInstruction(index4+1, ldcStore);
			instructions.addInstruction(index4+2, istore);


			// Extra, method5811
//			Instruction aloadClone3 = aloadPBN.clone();
//			aloadClone3.lookup();
//			instructions.addInstruction(index1 + 9, aloadClone3);
//
//			Instruction getfieldClone3 = getfieldPB.clone();
//			getfieldClone3.lookup();
//			instructions.addInstruction(index1 + 10, getfieldClone3);
//
//			Instruction sevBipush = new LDC(instructions, 10061); // new BiPush(instructions, Byte.parseByte("0"));
//			sevBipush.lookup();
//			instructions.addInstruction(index1 + 11, sevBipush);
//
//			Instruction eigBipush = new LDC(instructions, 23275811);
//			eigBipush.lookup();
//			instructions.addInstruction(index1 + 12, eigBipush);
//
//			Instruction method5811 = new InvokeVirtual(instructions, new net.runelite.asm.pool.Method(new Class("kj"), "cf", new Signature("(II)V")));
//			method5811.lookup();
//			instructions.addInstruction(index1 + 13, method5811);

//			Signature.Builder builderPnt = new Signature.Builder().addArgument(Type.INT).setReturnType(Type.VOID);
//			Instruction getstat = new GetStatic(instructions, new Field(new Class("java/lang/System"), "out", new Type("Ljava/io/PrintStream;")));
//			Instruction bipPrint = new BiPush(instructions, Byte.parseByte("9"));
//			Instruction pnt = new InvokeVirtual(instructions, new net.runelite.asm.pool.Method(new Class("java/io/PrintStream"), "println", new Signature(builderPnt.build())));
//			getstat.lookup();
//			bipPrint.lookup();
//			pnt.lookup();
//			instructions.addInstruction(index1 + 14, getstat);
//			instructions.addInstruction(index1 + 15, bipPrint);
//			instructions.addInstruction(index1 + 16, pnt);


			logger.info("Injected method hook {} in {} with {} args: {}, ins: {}",
				hookName, vanillaMethod, signature.size(),
				signature.getArguments(), instructions.getInstructions());
		}

//		if (hookName.equals(bypassNetSocket)) {
//			// Want to set up some logging here :)
//			Signature.Builder builderPnt = new Signature.Builder().addArgument(Type.INT).setReturnType(Type.VOID);
//
//			Instruction getstat = new GetStatic(instructions, new Field(new Class("java/lang/System"), "out", new Type("Ljava/io/PrintStream;")));
//			Instruction bipPrint = new BiPush(instructions, Byte.parseByte("9"));
//			Instruction pnt = new InvokeVirtual(instructions, new net.runelite.asm.pool.Method(new Class("java/io/PrintStream"), "println", new Signature(builderPnt.build())));
//
//			getstat.lookup();
//			bipPrint.lookup();
//			pnt.lookup();
//
//			instructions.addInstruction(1, getstat);
//			instructions.addInstruction(2, bipPrint);
//			instructions.addInstruction(3, pnt);
//
//			logger.info("Injected method hook {} in {} with {} args: {}, ins: {}",
//					hookName, vanillaMethod, signature.size(),
//					signature.getArguments(), instructions.getInstructions());
//		}

//		if (hookName.equals(bypassNS)) {
//			Signature.Builder builderPnt = new Signature.Builder().addArgument(Type.INT).setReturnType(Type.VOID);
//
//			// Arrays.toString(byteArray) instead of the decimal value..
//			Instruction aloadBuffer = instructions.getInstructions().get(6).clone();
//
//			Instruction getstat = new GetStatic(instructions, new Field(new Class("java/lang/System"), "out", new Type("Ljava/io/PrintStream;")));
//			Instruction bipPrint = new BiPush(instructions, Byte.parseByte("9"));
//			Instruction pnt = new InvokeVirtual(instructions, new net.runelite.asm.pool.Method(new Class("java/io/PrintStream"), "println", new Signature(builderPnt.build())));
//
//			getstat.lookup();
//			bipPrint.lookup();
//			pnt.lookup();
//
//			instructions.addInstruction(1, getstat);
//			instructions.addInstruction(2, bipPrint);
//			instructions.addInstruction(3, pnt);
//
//			// Try to print the buffer that the BufferedSource uses.
//			instructions.replace(bipPrint, aloadBuffer);
//
//			logger.info("Injected method hook {} in {} with {} args: {}, ins: {}",
//					hookName, vanillaMethod, signature.size(),
//					signature.getArguments(), instructions.getInstructions());
//		}

		// prints item swapping in inventory
//		if (hookName.equals(clientSP)) {
//			Instruction replace = null;
//
//			for (Instruction i : instructions.getInstructions()) {
//				if (i.toString().equals("net.runelite.asm.attributes.code.instructions.ALoad@26206172 in client.fu(I)V")) {
//					replace = i;
//				}
//			}
//
//			assert replace != null;
//
//			int index = instructions.getInstructions().indexOf(replace);
//			Instruction widgetClone = instructions.getInstructions().get(index+2).clone();
//			Instruction widgetField = instructions.getInstructions().get(index+3).clone();
//			Instruction ldcClone = instructions.getInstructions().get(index+4).clone();
//			Instruction widgetMul = instructions.getInstructions().get(index+5).clone();
//
//			Instruction iloadClone = instructions.getInstructions().get(index+11).clone();
//
//			Instruction itemDest = instructions.getInstructions().get(index+17).clone();
//			Instruction ldcDest = instructions.getInstructions().get(index+18).clone();
//			Instruction mulDest = instructions.getInstructions().get(index+19).clone();
//
//			Instruction itemSrc = instructions.getInstructions().get(index+25).clone();
//			Instruction ldcSrc = instructions.getInstructions().get(index+26).clone();
//			Instruction mulSrc = instructions.getInstructions().get(index+27).clone();
//
//
//			Signature.Builder builderWidget = new Signature.Builder().addArgument(Type.INT).setReturnType(Type.VOID);
//			Instruction getstat = new GetStatic(instructions, new Field(new Class("java/lang/System"), "out", new Type("Ljava/io/PrintStream;")));
//			Instruction prnt = new InvokeVirtual(instructions, new net.runelite.asm.pool.Method(new Class("java/io/PrintStream"), "println", new Signature(builderWidget.build())));
//
//			instructions.addInstruction(index+2, getstat);
//			instructions.addInstruction(index+3, widgetClone);
//			instructions.addInstruction(index+4, widgetField);
//			instructions.addInstruction(index+5, ldcClone);
//			instructions.addInstruction(index+6, widgetMul);
//			instructions.addInstruction(index+7, prnt);
//
//			instructions.addInstruction(index+17, getstat.clone());
//			instructions.addInstruction(index+18, iloadClone);
//			instructions.addInstruction(index+19, prnt.clone());
//
//			instructions.addInstruction(index+26, getstat.clone());
//			instructions.addInstruction(index+27, itemDest);
//			instructions.addInstruction(index+28, ldcDest);
//			instructions.addInstruction(index+29, mulDest);
//			instructions.addInstruction(index+30, prnt.clone());
//
//			instructions.addInstruction(index+39, getstat.clone());
//			instructions.addInstruction(index+40, itemSrc);
//			instructions.addInstruction(index+41, ldcSrc);
//			instructions.addInstruction(index+42, mulSrc);
//			instructions.addInstruction(index+43, prnt.clone());
//
//
//			logger.info("Injected method hook {} in {} with  ins {}",
//					hookName, vanillaMethod, instructions.getInstructions());
//		}

		// prints x,y mouse coords?
//		if (hookName.equals(clientSP)) {
//			Instruction replace = null;
//
//			for (Instruction i : instructions.getInstructions()) {
//				if (i.toString().equals("net.runelite.asm.attributes.code.instructions.ALoad@153c7434 in client.fu(I)V")) {
//					replace = i;
//				}
//			}
//
//			assert replace != null;
//
//			int index = instructions.getInstructions().indexOf(replace);
//
//			Instruction xcopy = instructions.getInstructions().get(index+2).clone();
//			Instruction ycopy = instructions.getInstructions().get(index+8).clone();
//
//			Instruction tmp = instructions.getInstructions().get(index+8);
//			instructions.replace(tmp, new LDC(instructions, 0));
//
//			Instruction tmp2 = instructions.getInstructions().get(index+2);
//			instructions.replace(tmp2, new LDC(instructions, 0));
//
//			Signature.Builder builderWidget = new Signature.Builder().addArgument(Type.INT).setReturnType(Type.VOID);
//			Instruction getstat = new GetStatic(instructions, new Field(new Class("java/lang/System"), "out", new Type("Ljava/io/PrintStream;")));
//			Instruction prnt = new InvokeVirtual(instructions, new net.runelite.asm.pool.Method(new Class("java/io/PrintStream"), "println", new Signature(builderWidget.build())));
//
//			instructions.addInstruction(index+2, getstat);
//			instructions.addInstruction(index+3, xcopy);
//			instructions.addInstruction(index+4, prnt);
//
//			instructions.addInstruction(index+11, getstat.clone());
//			instructions.addInstruction(index+12, ycopy);
//			instructions.addInstruction(index+13, prnt.clone());
//		}

		// trying to mess with the GE
//		if (hookName.equals(cthree)) {
//			Instruction replace = null;
//
//			for (Instruction i : instructions.getInstructions()) {
//				//if (i.toString().equals("getstatic static Lgj; gj.i in static aw.hf(IIIILjava/lang/String;Ljava/lang/String;IIB)V")) {
//
//				if (i.toString().equals("net.runelite.asm.attributes.code.instructions.IAdd@646346de in static aw.hf(IIIILjava/lang/String;Ljava/lang/String;IIB)V")) {
//					replace = i;
//				}
//			}
//
//			assert replace != null;
//
//			int index = instructions.getInstructions().indexOf(replace);
//
//			Instruction ldcClone = instructions.getInstructions().get(index-4).clone();
//			Instruction statClone = instructions.getInstructions().get(index-3).clone();
//			Instruction mulClone = instructions.getInstructions().get(index-2).clone();
//			Instruction iloadClone = instructions.getInstructions().get(index-1).clone();
//			Instruction repClone = replace.clone();
//			// print this
//
//			Instruction iload0Clone = instructions.getInstructions().get(index+6).clone();
//			Instruction statClone1 = instructions.getInstructions().get(index+7).clone();
//			Instruction ldcClone1 = instructions.getInstructions().get(index+8).clone();
//			Instruction mulClone1 = instructions.getInstructions().get(index+9).clone();
//			Instruction addClone1 = instructions.getInstructions().get(index+10).clone();
//			// print this
//
//			// Don't know if we can get <0, 1>
//
//			// Print iload4
//			Instruction iload4 = new ILoad(instructions, 3);
//
//			Signature.Builder builderWidget = new Signature.Builder().addArgument(Type.INT).setReturnType(Type.VOID);
//			Instruction getstat = new GetStatic(instructions, new Field(new Class("java/lang/System"), "out", new Type("Ljava/io/PrintStream;")));
//			Instruction prnt = new InvokeVirtual(instructions, new net.runelite.asm.pool.Method(new Class("java/io/PrintStream"), "println", new Signature(builderWidget.build())));
//
//			instructions.addInstruction(index+1, getstat);
//			instructions.addInstruction(index+2, ldcClone);
//			instructions.addInstruction(index+3, statClone);
//			instructions.addInstruction(index+4, mulClone);
//			instructions.addInstruction(index+5, iloadClone);
//			instructions.addInstruction(index+6, repClone);
//			instructions.addInstruction(index+7, prnt);
//
//			instructions.addInstruction(index+8, getstat.clone());
//			instructions.addInstruction(index+9, iload0Clone);
//			instructions.addInstruction(index+10, statClone1);
//			instructions.addInstruction(index+11, ldcClone1);
//			instructions.addInstruction(index+12, mulClone1);
//			instructions.addInstruction(index+13, addClone1);
//			instructions.addInstruction(index+14, prnt.clone());
//
//			// figure out iload...
//			instructions.addInstruction(index+15, getstat.clone());
//			instructions.addInstruction(index+16, iload4);
//			instructions.addInstruction(index+17, prnt.clone());
//
//			// 3487
//			// 3164
//			// 10061
//			// this actually walks me to the GE from a decent distance
//
//			// test to see if it matters ur x,y position or not or if this just merely brings up an *interface* :)
//			// can we do GE in tourney worlds and x-fer money ;) ?
//		}

		// All clicked widgets
		if (hookName.equals(cthree)) {
			// Had to disable the mixin...
			// This gives us *most* widgets that are being clicked

			Instruction replace = null;

			for (Instruction i : instructions.getInstructions()) {
				if (i.toString().equals("label iload 2 in static aw.hf(IIIILjava/lang/String;Ljava/lang/String;IIB)V on line number 7601")) {
					replace = i;
				}
			}

			assert replace != null;

			int index = instructions.getInstructions().indexOf(replace);

			Instruction iloadCopy = instructions.getInstructions().get(index+1).clone();

			Signature.Builder builderWidget = new Signature.Builder().addArgument(Type.INT).setReturnType(Type.VOID);
			Instruction getstat = new GetStatic(instructions, new Field(new Class("java/lang/System"), "out", new Type("Ljava/io/PrintStream;")));
			Instruction prnt = new InvokeVirtual(instructions, new net.runelite.asm.pool.Method(new Class("java/io/PrintStream"), "println", new Signature(builderWidget.build())));

			instructions.addInstruction(index+1, getstat);
			instructions.addInstruction(index+2, iloadCopy);
			instructions.addInstruction(index+3, prnt);

			Instruction iload0 = new ILoad(instructions, 0);
			Instruction iload1 = new ILoad(instructions, 1);
			Instruction iload3 = new ILoad(instructions, 3);

			instructions.addInstruction(index+4, getstat.clone());
			instructions.addInstruction(index+5, iload3);
			instructions.addInstruction(index+6, prnt.clone());

			instructions.addInstruction(index+7, getstat.clone());
			instructions.addInstruction(index+8, iload0);
			instructions.addInstruction(index+9, prnt.clone());

			instructions.addInstruction(index+10, getstat.clone());
			instructions.addInstruction(index+11, iload1);
			instructions.addInstruction(index+12, prnt.clone());

			instructions.addInstruction(index+1, getstat.clone());
			instructions.addInstruction(index+2, new LDC(instructions, 100000));
			instructions.addInstruction(index+3, prnt.clone());

			instructions.addInstruction(index+16, getstat.clone());
			instructions.addInstruction(index+17, new LDC(instructions, 100001));
			instructions.addInstruction(index+18, prnt.clone());

			// shoot gnomeball
			//3
			//2393
			//76
			//56

			//35
			//10526
			//4
			//9764864

			//34
			//10526
			//4
			//9764864

			//35
			//10526
			//4
			//9764864

			//33
			//10526
			//4
			//9764864

			logger.info("Injected method hook {} in {} with {} args: {}, ins: {}",
					hookName, vanillaMethod, signature.size(),
					signature.getArguments(), instructions.getInstructions());
		}

		if (hookName.equals(wmap)) {
			// This should give us the exact calls of the widgets that have code 57

			Instruction replace = null;

			for (Instruction i : instructions.getInstructions()) {
				if (i.toString().equals("label iload 1 in static ac.ik(IIIILjava/lang/String;B)V on line number 8483")) {
					replace = i;
				}
			}

			assert replace != null;

			int index = instructions.getInstructions().indexOf(replace);

			Instruction var0Load = new ILoad(instructions, 0);
			Instruction var1Load = new ILoad(instructions, 1);
			Instruction var2Load = new ILoad(instructions, 2);
			Instruction var3Load = new ILoad(instructions, 3);

			Signature.Builder builderWidget = new Signature.Builder().addArgument(Type.INT).setReturnType(Type.VOID);
			Instruction getstat = new GetStatic(instructions, new Field(new Class("java/lang/System"), "out", new Type("Ljava/io/PrintStream;")));
			Instruction prnt = new InvokeVirtual(instructions, new net.runelite.asm.pool.Method(new Class("java/io/PrintStream"), "println", new Signature(builderWidget.build())));

			instructions.addInstruction(index+1, getstat);
			instructions.addInstruction(index+2, var0Load);
			instructions.addInstruction(index+3, prnt);
			instructions.addInstruction(index+4, getstat.clone());
			instructions.addInstruction(index+5, var1Load);
			instructions.addInstruction(index+6, prnt.clone());
			instructions.addInstruction(index+7, getstat.clone());
			instructions.addInstruction(index+8, var2Load);
			instructions.addInstruction(index+9, prnt.clone());
			instructions.addInstruction(index+10, getstat.clone());
			instructions.addInstruction(index+11, var3Load);
			instructions.addInstruction(index+12, prnt.clone());

			// POH
			//1
			//14286876
			//-1
			//-1

			// GE BUY
			//1
			//30474250
			//3
			//-1

			// GE SELL
			//1
			//30474250
			//4
			//-1

			//GE SELL BRONZE KITE 1st inv slot
			//1
			//30605312
			//1
			//1189

			//GE SELL BRONZE KITE HIT ACCEPT
			//1
			//30474267
			//-1
			//-1

			//BANK certain index
			//2
			//983043
			//0
			//8013

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
