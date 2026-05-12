# Java Reverse Engineering Patterns

## Archive Formats

| Format | Magic | Structure | Tool |
|--------|-------|-----------|------|
| `.class` | `0xCAFEBABE` | Single class file | CFR, javap |
| `.jar` | `PK` (ZIP) | META-INF/MANIFEST.MF + *.class | CFR, Procyon |
| `.war` | `PK` (ZIP) | WEB-INF/web.xml + *.class | Same as JAR |
| `.ear` | `PK` (ZIP) | META-INF/application.xml | Extract + recurse |
| `.apk` | `PK` (ZIP) | classes.dex + AndroidManifest.xml | JADX, dex2jar |

## Class File Structure

```
ClassFile {
    u4             magic;          // 0xCAFEBABE
    u2             minor_version;
    u2             major_version;  // 52=Java 8, 55=Java 11, 61=Java 17
    u2             constant_pool_count;
    cp_info        constant_pool[constant_pool_count-1];
    u2             access_flags;
    u2             this_class;
    u2             super_class;
    // ... interfaces, fields, methods, attributes
}
```

### Major version → Java version
| Major | Java | Major | Java |
|-------|------|-------|------|
| 45 | 1.1 | 55 | 11 |
| 49 | 5 | 58 | 14 |
| 50 | 6 | 61 | 17 |
| 51 | 7 | 63 | 19 |
| 52 | 8 | 65 | 21 |

## Decompiler Comparison

### CFR (best overall)
```bash
# Download: https://github.com/leibnitz27/cfr/releases
java -jar cfr.jar target.jar --outputdir src/
java -jar cfr.jar MyClass.class --outputdir src/
# Handles: generics, lambdas, switch expressions, records
# Set env: CFR_JAR=path/to/cfr.jar
```

### Procyon (best for complex generics)
```bash
# Download: https://github.com/mstrobel/procyon/releases
java -jar procyon-decompiler.jar -o src/ target.jar
# Set env: PROCYON_JAR=path/to/procyon-decompiler.jar
```

### FernFlower (IntelliJ-style)
```bash
# Download: https://github.com/fesh0r/fernflower/releases
java -jar fernflower.jar target.jar src/
# Outputs a JAR containing .java source
# Set env: FERNFLOWER_JAR=path/to/fernflower.jar
```

### JADX (best for APK)
```bash
# Install: https://github.com/skylot/jadx/releases
jadx target.apk -d src/ --no-res  # skip resources for speed
jadx target.apk -d src/           # include resources
```

### javap (fallback, bytecode only)
```bash
javap -c -p MyClass               # bytecode + private members
javap -v MyClass                   # verbose (constant pool)
```

## Obfuscator Patterns

### ProGuard (most common)
- Single-letter class names: `a.class`, `b.class`
- Short package names: `a/b/c.class`
- Mapping file: `proguard.map` or `mapping.txt`
- Retrace: `retrace.bat mapping.txt stacktrace.txt`

### Allatori
- String encryption with decrypt method in each class
- Watermark in class attributes
- Look for: static initializer blocks with byte array XOR

### ZKM (Zelix KlassMaster)
- Aggressive flow obfuscation
- String encryption with reflection-based decryption
- Exception-based control flow

### Stringer
- Heavy string encryption
- Dedicated decryption class
- Look for: `Stringer Java Obfuscator` watermark

## License Patterns in Java

### Common license check flow
```java
public class LicenseManager {
    public boolean validateLicense(String key) {
        // 1. Check format: XXXXX-XXXXX-XXXXX-XXXXX
        if (!key.matches("[A-Z0-9]{5}(-[A-Z0-9]{5}){3}")) return false;
        
        // 2. Verify checksum (last group)
        String check = computeChecksum(key.substring(0, key.lastIndexOf('-')));
        if (!check.equals(key.substring(key.lastIndexOf('-') + 1))) return false;
        
        // 3. Check HWID binding
        String hwid = getHardwareId();
        if (!verifyBinding(key, hwid)) return false;
        
        // 4. Check expiry
        Date expiry = extractExpiry(key);
        return !expiry.before(new Date());
    }
}
```

### Patching approaches
1. **Bytecode edit**: Modify `.class` to return `true` (change `ireturn` after `iconst_0` → `iconst_1`)
2. **Java Agent**: `-javaagent:patch.jar` to intercept at load time
3. **Classpath priority**: Place modified class before original JAR in classpath
4. **Reflection**: Modify final fields at runtime via `setAccessible(true)`

### JVM bytecode for license bypass
```
Original:                    Patched:
  aload_1                      aload_1
  invokevirtual check          pop
  ifeq FAIL                    iconst_1
  iconst_1                     ireturn
  ireturn
FAIL:
  iconst_0
  ireturn
```

## Android APK Specifics

### DEX vs JVM bytecode
- APK uses Dalvik Executable (DEX) format, not JVM `.class`
- DEX is register-based, JVM is stack-based
- `dex2jar` converts DEX → JVM bytecode → decompile with CFR
- JADX directly DEX → Java source (better results)

### APK structure
```
app.apk
├── AndroidManifest.xml    (binary XML — use aapt or apktool)
├── classes.dex            (main code)
├── classes2.dex           (multidex)
├── res/                   (resources)
├── lib/                   (native .so libraries)
├── assets/                (raw assets)
└── META-INF/              (signing info)
```

### Key files to check
- `AndroidManifest.xml`: permissions, activities, receivers, services
- `res/values/strings.xml`: hardcoded strings (API URLs, keys)
- `assets/`: config files, embedded databases, license files
- `lib/`: native libraries (may contain license check in C/C++)
