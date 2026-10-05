import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.time.Instant
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

abstract class EmbedProxyJarTask : DefaultTask() {
    @get:InputFile
    abstract val shadowJarFile: RegularFileProperty

    // Only the one proxy JAR actually read — NOT the whole project directory, which Gradle
    // can't reliably snapshot as a task input (it chokes trying to hash its own build/cache
    // files living under the project root).
    @get:InputFile
    abstract val proxyJarInputFile: RegularFileProperty

    // Declared separately from shadowJarFile (even though it resolves to the same path) so
    // Gradle has a registered output to track for this task, instead of the task silently
    // mutating its declared input.
    @get:OutputFile
    abstract val outputJarFile: RegularFileProperty

    @TaskAction
    fun embedJar() {
        val shadowJar = shadowJarFile.get().asFile
        val proxyJarFile = proxyJarInputFile.get().asFile

        if (!proxyJarFile.exists()) {
            throw GradleException("Proxy JAR not found at: ${proxyJarFile.absolutePath}")
        }

        // Write the merged archive into the task's own temp directory so a failure never
        // leaves a stray .tmp file behind, and the input jar is never touched until the
        // new archive has been fully and successfully built.
        val tempFile = File(temporaryDir, "${shadowJar.name}.tmp")
        tempFile.delete()

        try {
            ZipOutputStream(tempFile.outputStream().buffered()).use { zos ->
                // Copy existing entries from shadow JAR (read-only; input is never modified)
                ZipInputStream(shadowJar.inputStream().buffered()).use { zis ->
                    var entry = zis.nextEntry
                    while (entry != null) {
                        zos.putNextEntry(ZipEntry(entry.name))
                        zis.copyTo(zos)
                        zos.closeEntry()
                        entry = zis.nextEntry
                    }
                }
                // Add proxy JAR
                zos.putNextEntry(ZipEntry(proxyJarFile.name))
                proxyJarFile.inputStream().buffered().use { it.copyTo(zos) }
                zos.closeEntry()
            }

            // Only now that the new archive was written successfully, publish it atomically.
            val output = outputJarFile.get().asFile
            Files.move(tempFile.toPath(), output.toPath(), StandardCopyOption.REPLACE_EXISTING)
        } finally {
            tempFile.delete()
        }

        logger.lifecycle("Embedded proxy JAR into ${outputJarFile.get().asFile.name}")
    }
}

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.ktor)
    java
}

group = providers.gradleProperty("group").get()
version = providers.gradleProperty("version").get()
description = providers.gradleProperty("description").get()

dependencies {
    compileOnly(libs.burp.montoya.api)

    implementation(libs.bundles.ktor.server)
    implementation(libs.kotlin.stdlib)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.mcp.kotlin.sdk)

    testImplementation(libs.bundles.test.framework)
    testImplementation(libs.bundles.ktor.test)
    testImplementation(libs.burp.montoya.api)
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(providers.gradleProperty("java.toolchain.version").get().toInt()))
    }
}

kotlin {
    jvmToolchain {
        languageVersion.set(JavaLanguageVersion.of(providers.gradleProperty("java.toolchain.version").get().toInt()))
    }

    compilerOptions {
        apiVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_2)
        languageVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_2_2)
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
        freeCompilerArgs.addAll(
            "-Xjsr305=strict"
        )
    }
}

application {
    mainClass.set("net.portswigger.mcp.ExtensionBase")
}

tasks {
    test {
        useJUnitPlatform()
        systemProperty("file.encoding", "UTF-8")

        testLogging {
            events("passed", "skipped", "failed")
            showExceptions = true
            showCauses = true
            showStackTraces = true
        }
    }

    jar {
        enabled = false
    }

    shadowJar {
        archiveClassifier.set("")
        archiveBaseName.set("burp-mcp-ColorStrike")
        archiveVersion.set("v${project.version}")
        mergeServiceFiles()

        manifest {
            attributes(
                mapOf(
                    "Implementation-Title" to project.name,
                    "Implementation-Version" to project.version,
                    "Implementation-Vendor" to "geozin",
                    "Built-By" to System.getProperty("user.name"),
                    "Built-Date" to Instant.now().toString(),
                    "Built-JDK" to "${System.getProperty("java.version")} (${System.getProperty("java.vendor")} ${
                        System.getProperty("java.vm.version")
                    })",
                    "Created-By" to "Gradle ${gradle.gradleVersion}"
                )
            )
        }


        exclude("META-INF/*.SF")
        exclude("META-INF/*.DSA")
        exclude("META-INF/*.RSA")
        exclude("META-INF/INDEX.LIST")
        exclude("META-INF/DEPENDENCIES")
        exclude("META-INF/NOTICE*")
        exclude("META-INF/LICENSE*")
        exclude("module-info.class")

        duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    }

    val embedProxyJar = register<EmbedProxyJarTask>("embedProxyJar") {
        group = "build"
        description = "Embeds the MCP proxy JAR into the shadow JAR"
        dependsOn(shadowJar)
        shadowJarFile.set(shadowJar.flatMap { it.archiveFile })
        proxyJarInputFile.set(layout.projectDirectory.file("libs/mcp-proxy-all.jar"))
        outputJarFile.set(shadowJar.flatMap { it.archiveFile })
    }

    // Anything that reads the shadow jar's archive file must run after embedProxyJar has
    // patched it in place — depending only on shadowJar races with embedProxyJar, since both
    // write/read the same output path. (Only startShadowScripts does today; add further
    // dependents here if the shadow distribution tasks are ever invoked alongside embedProxyJar.)
    named("startShadowScripts") {
        dependsOn(embedProxyJar)
    }

    build {
        dependsOn(shadowJar)
    }

    withType<AbstractArchiveTask>().configureEach {
        isPreserveFileTimestamps = false
        isReproducibleFileOrder = true
    }
}

tasks.wrapper {
    gradleVersion = "9.2.0"
    distributionType = Wrapper.DistributionType.BIN
}
