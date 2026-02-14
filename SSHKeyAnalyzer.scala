#!/usr/bin/env scala

import java.io.File
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.Base64
import scala.io.Source
import scala.util.{Try, Success, Failure}

object SSHKeyAnalyzer {
  val VERSION = "0.65-scala"

  case class Config(
    filename: String = "",
    showSshfp: Boolean = false,
    showExponent: Boolean = false,
    debug: Boolean = false
  )

  case class KeyInfo(
    line: Int,
    keyType: String,
    modBits: Int,
    exponent: String,
    fpMd5: String,
    fpSha256: String,
    comment: String,
    typeVer: String = "",
    failed: Boolean = false
  )

  def main(args: Array[String]): Unit = {
    val config = parseArgs(args)

    if (config.filename.isEmpty) {
      printUsage()
      sys.exit(1)
    }

    analyzeKeyFile(config)
  }

  def parseArgs(args: Array[String]): Config = {
    var config = Config()
    var i = 0

    while (i < args.length) {
      args(i) match {
        case "-h" | "--help" | "-?" | "-v" =>
          printInfo()
          printUsage()
          sys.exit(0)
        case "-s" | "--sha" | "--sshfp" =>
          config = config.copy(showSshfp = true)
        case "-e" | "--exponent" =>
          config = config.copy(showExponent = true)
        case "-d" | "--debug" =>
          config = config.copy(debug = true)
        case other =>
          if (config.filename.isEmpty) {
            config = config.copy(filename = other)
          }
      }
      i += 1
    }

    config
  }

  def analyzeKeyFile(config: Config): Unit = {
    val file = new File(config.filename)
    if (!file.exists()) {
      println(s"Error: File not found: ${config.filename}")
      sys.exit(1)
    }

    var headerPrinted = false

    Try(Source.fromFile(file)) match {
      case Success(source) =>
        try {
          source.getLines().zipWithIndex.foreach { case (line, idx) =>
            val lineNum = idx + 1
            val trimmed = line.trim

            // Skip empty lines and comments
            if (trimmed.nonEmpty && !trimmed.startsWith("#")) {
              val keyInfoOpt = parseLine(trimmed, lineNum, config)

              keyInfoOpt.foreach { keyInfo =>
                if (!headerPrinted) {
                  printHeader(config)
                  headerPrinted = true
                }
                printKeyInfo(keyInfo, config)
              }
            }
          }
          } finally {
            source.close()
          }
      case Failure(exception) =>
        println(s"Error reading file: ${exception.getMessage}")
        sys.exit(1)
    }
  }

  def parseLine_bad(line: String, lineNum: Int, config: Config): Option[KeyInfo] = {
    // Extract key string and comment
    val keyPattern = """([a-zA-Z0-9+=\/]{65,})\s*(.*)$""".r

    keyPattern.findFirstMatchIn(line) match {
      case Some(m) =>
        val keyString = m.group(1)
        val comment = m.group(2)

        // Check if it looks like SSH-1 key
        if (keyString.matches(".*[0-9]{30,}.*")) {
          Some(KeyInfo(
            line = lineNum,
            keyType = "ssh-1",
            modBits = 0,
            exponent = "n/a",
            fpMd5 = "not_implemented",
            fpSha256 = "not_implemented",
            comment = comment,
            failed = true
          ))
        } else {
          decodePublicKey(keyString, lineNum, comment, config)
        }
      case None =>
        None
    }
  }

  def parseLine(line: String, lineNum: Int, config: Config): Option[KeyInfo] = {
    // Split line into fields
    val fields = line.trim.split("\\s+", 3)

    if (fields.length < 2) {
      return None
    }

    // Handle options at start (like from="host" or command="...")
    val (keyType, keyData, comment) = if (fields(0).matches("ssh-.*|ecdsa-.*")) {
      // Standard format: keytype keydata [comment]
      (fields(0), fields(1), if (fields.length > 2) fields(2) else "")
    } else if (fields.length >= 3 && fields(1).matches("ssh-.*|ecdsa-.*")) {
      // Options format: options keytype keydata [comment]
      (fields(1), fields(2), if (fields.length > 3) fields.drop(3).mkString(" ") else "")
    } else {
      // Try to find ssh key type in the line
      val sshTypeIdx = fields.indexWhere(_.matches("ssh-.*|ecdsa-.*"))
      if (sshTypeIdx >= 0 && sshTypeIdx + 1 < fields.length) {
        (fields(sshTypeIdx), fields(sshTypeIdx + 1), 
          if (fields.length > sshTypeIdx + 2) fields.drop(sshTypeIdx + 2).mkString(" ") else "")
          } else {
            return None
          }
    }

    // Check if it looks like SSH-1 key (old format with numbers)
    if (keyData.matches(".*[0-9]{30,}.*")) {
      Some(KeyInfo(
        line = lineNum,
        keyType = "ssh-1",
        modBits = 0,
        exponent = "n/a",
        fpMd5 = "not_implemented",
        fpSha256 = "not_implemented",
        comment = comment,
        failed = true
      ))
    } else {
      decodePublicKey(keyData, lineNum, comment, config)
    }
  }

  def decodePublicKey(keyString: String, lineNum: Int, comment: String, config: Config): Option[KeyInfo] = {
    Try {
      val bytes = Base64.getDecoder.decode(keyString)
      val buffer = ByteBuffer.wrap(bytes)

      // Compute fingerprints
      val fpMd5 = computeMd5Fingerprint(bytes)
      val fpSha256 = if (config.showSshfp) computeSha256Fingerprint(bytes) else ""

      // Read type length
      val typeLen = buffer.getInt()

      if (typeLen <= 1 || typeLen >= 20) {
        throw new Exception("Invalid key type length")
      }

      // Read key type
      val typeBytes = new Array[Byte](typeLen)
      buffer.get(typeBytes)
      val keyType = new String(typeBytes, "UTF-8")

      if (config.debug) {
        println(s"DEBUG: Key type: $keyType")
      }

      // Parse based on key type
      keyType match {
        case t if t.contains("rsa") =>
          parseRsaKey(buffer, keyType, lineNum, comment, fpMd5, fpSha256, config)
        case t if t.contains("dss") =>
          parseDssKey(buffer, keyType, lineNum, comment, fpMd5, fpSha256, config)
        case t if t.contains("ecdsa") =>
          parseEcdsaKey(buffer, keyType, lineNum, comment, fpMd5, fpSha256, config)
        case t if t.contains("ed25519") =>
          parseEd25519Key(buffer, keyType, lineNum, comment, fpMd5, fpSha256, config)
        case _ =>
          throw new Exception(s"Unknown key type: $keyType")
      }
  }.toOption.flatten.orElse {
    Some(KeyInfo(
      line = lineNum,
      keyType = "n/a",
      modBits = 0,
      exponent = "n/a",
      fpMd5 = "could_not_decode",
      fpSha256 = "could_not_decode",
      comment = comment,
      failed = true
    ))
  }
  }

  def parseRsaKey_bad(buffer: ByteBuffer, keyType: String, lineNum: Int, comment: String, 
    fpMd5: String, fpSha256: String, config: Config): Option[KeyInfo] = {
      // RSA: exponent then modulus
      val expLen = buffer.getInt()
      val expBytes = new Array[Byte](expLen)
      buffer.get(expBytes)
      val exponent = BigInt(1, expBytes).toString(10)

      val modLen = buffer.getInt()
      val modBits = (modLen - 1) * 8

      Some(KeyInfo(
        line = lineNum,
        keyType = keyType,
        modBits = modBits,
        exponent = exponent,
        fpMd5 = fpMd5,
        fpSha256 = fpSha256,
        comment = comment,
        typeVer = "1"
      ))
  }

  def parseRsaKey(buffer: ByteBuffer, keyType: String, lineNum: Int, comment: String,
    fpMd5: String, fpSha256: String, config: Config): Option[KeyInfo] = {
      try {
        // RSA: exponent then modulus
        val expLen = buffer.getInt()
        if (config.debug) {
          println(s"DEBUG: RSA expLen=$expLen, buffer remaining=${buffer.remaining()}")
        }

        val expBytes = new Array[Byte](expLen)
        buffer.get(expBytes)
        val exponent = BigInt(1, expBytes).toString(10)

        val modLen = buffer.getInt()
        if (config.debug) {
          println(s"DEBUG: RSA modLen=$modLen, buffer remaining=${buffer.remaining()}")
        }

        val modBytes = new Array[Byte](modLen)
        buffer.get(modBytes)
        val modulus = BigInt(1, modBytes)
        val modBits = modulus.bitLength

        if (config.debug) {
          println(s"DEBUG: RSA successful - modBits=$modBits")
        }

        Some(KeyInfo(
          line = lineNum,
          keyType = keyType,
          modBits = modBits,
          exponent = exponent,
          fpMd5 = fpMd5,
          fpSha256 = fpSha256,
          comment = comment,
          typeVer = "1"
        ))
      } catch {
        case e: Exception =>
          if (config.debug) {
            println(s"DEBUG: RSA parse failed - ${e.getClass.getSimpleName}: ${e.getMessage}")
            e.printStackTrace()
          }
          None
      }
  }

  def parseDssKey(buffer: ByteBuffer, keyType: String, lineNum: Int, comment: String,
    fpMd5: String, fpSha256: String, config: Config): Option[KeyInfo] = {
      // DSS: modulus then exponent
      val modLen = buffer.getInt()
      val modBits = (modLen - 1) * 8

      Some(KeyInfo(
        line = lineNum,
        keyType = keyType,
        modBits = modBits,
        exponent = "n/a",
        fpMd5 = fpMd5,
        fpSha256 = fpSha256,
        comment = comment,
        typeVer = "2"
      ))
  }

  def parseEcdsaKey(buffer: ByteBuffer, keyType: String, lineNum: Int, comment: String,
    fpMd5: String, fpSha256: String, config: Config): Option[KeyInfo] = {
      // ECDSA: domain parameters, then public key
      val paramLen = buffer.getInt()
      buffer.position(buffer.position() + paramLen)

      val modLen = buffer.getInt()
      val modBits = (modLen - 1) * 8 / 2

      Some(KeyInfo(
        line = lineNum,
        keyType = keyType,
        modBits = modBits,
        exponent = "n/a",
        fpMd5 = fpMd5,
        fpSha256 = fpSha256,
        comment = comment,
        typeVer = "3"
      ))
  }

  def parseEd25519Key(buffer: ByteBuffer, keyType: String, lineNum: Int, comment: String,
    fpMd5: String, fpSha256: String, config: Config): Option[KeyInfo] = {
      val modLen = buffer.getInt()
      val modBits = (modLen - 1) * 8

      Some(KeyInfo(
        line = lineNum,
        keyType = keyType,
        modBits = modBits,
        exponent = "n/a",
        fpMd5 = fpMd5,
        fpSha256 = fpSha256,
        comment = comment,
        typeVer = "4"
      ))
  }

  def computeMd5Fingerprint(bytes: Array[Byte]): String = {
    val md5 = MessageDigest.getInstance("MD5")
    val digest = md5.digest(bytes)
    digest.map(b => f"${b & 0xff}%02x").mkString(":")
  }

  def computeSha256Fingerprint(bytes: Array[Byte]): String = {
    val sha256 = MessageDigest.getInstance("SHA-256")
    val digest = sha256.digest(bytes)
    Base64.getEncoder.withoutPadding().encodeToString(digest)
  }

  def printHeader(config: Config): Unit = {
    if (config.showSshfp) {
      println("Line  KeyType             Bits   \"SSHFP RR record\"                                    Comment")
      println("---- ------------------- ------ ---------------------------------------------------- -------------")
    } else if (config.showExponent) {
      println("Line  KeyType             Bits   Exponent    Fingerprint (MD5)                                 Comment")
      println("---- ------------------- ------ ----------- ------------------------------------------------- -------------")
    } else {
      println("Line  KeyType             Bits   Fingerprint (MD5)                                 Comment")
      println("---- ------------------- ------ ------------------------------------------------- -------------")
    }
  }

  def printKeyInfo(info: KeyInfo, config: Config): Unit = {
    val isTerminal = System.console() != null

    // Determine color based on key strength
    val color = if (isTerminal && !info.failed) {
      info.keyType.toLowerCase match {
        case t if t.contains("ed25519") || t.contains("ecdsa") => "\u001b[32m" // green
        case _ if info.modBits <= 1024 => "\u001b[31m" // red
        case _ if info.modBits < 2048 => "\u001b[33m" // yellow
        case _ if info.modBits >= 4096 => "\u001b[32m" // green
        case _ => "" // 2048-3072 bits - acceptable, no color
      }
    } else ""

    val reset = if (color.nonEmpty) "\u001b[0m" else ""

    if (config.showSshfp && !info.failed) {
      printf("%-4d %-20s %s%-6d%s \"SSHFP %s 2 %s\"  \"%s\"\n",
        info.line, info.keyType, color, info.modBits, reset, 
        info.typeVer, info.fpSha256, info.comment)
    } else if (config.showSshfp && info.failed) {
      printf("%-4d %-20s %-6s %-52s  \"%s\"\n",
        info.line, info.keyType, 
        if (info.modBits == 0) "n/a" else info.modBits.toString,
        info.fpSha256, info.comment)
    } else if (config.showExponent && !info.failed) {
      val expDisplay = if (info.exponent.length > 10) info.exponent.take(10) else info.exponent
      printf("%-4d %-20s %s%-6d%s %-11s %-49s \"%s\"\n",
        info.line, info.keyType, color, info.modBits, reset,
        expDisplay, info.fpMd5, info.comment)
    } else if (config.showExponent && info.failed) {
      printf("%-4d %-20s %-6s %-11s %-49s \"%s\"\n",
        info.line, info.keyType,
        if (info.modBits == 0) "n/a" else info.modBits.toString,
        info.exponent, info.fpMd5, info.comment)
    } else if (!info.failed) {
      printf("%-4d %-20s %s%-6d%s %-49s \"%s\"\n",
        info.line, info.keyType, color, info.modBits, reset,
        info.fpMd5, info.comment)
    } else {
      printf("%-4d %-20s %-6s %-49s \"%s\"\n",
        info.line, info.keyType,
        if (info.modBits == 0) "n/a" else info.modBits.toString,
        info.fpMd5, info.comment)
    }
  }

  def printUsage(): Unit = {
    println(s"Usage: SSHKeyAnalyzer [-h|--help] [-e|--exponent] [-s|--sha|--sshfp] [-d|--debug] public_key_file")
  }

  def printInfo(): Unit = {
    println(s"\u001b[33mSSHKeyAnalyzer\u001b[0m - $VERSION  (Scala ${scala.util.Properties.versionNumberString})")
  }
}
