// BoundAuth Android — Gradle multi-module (지시서 §6).
pluginManagement {
    repositories { gradlePluginPortal(); google(); mavenCentral() }
}
dependencyResolutionManagement {
    repositories { google(); mavenCentral() }
}
rootProject.name = "boundauth-android"
include(":boundauth-sdk")
include(":demo-app")
