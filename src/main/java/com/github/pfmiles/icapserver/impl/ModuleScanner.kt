package com.github.pfmiles.icapserver.impl

import com.github.pfmiles.icapserver.Module
import org.reflections.ReflectionUtils
import org.reflections.Reflections
import org.reflections.scanners.Scanners
import org.reflections.util.ConfigurationBuilder
import org.reflections.util.FilterBuilder
import org.slf4j.LoggerFactory


/**
 * Scan icap-server modules in the whole classpath, under a specified base package.
 *
 * @author pf-miles
 */
internal object ModuleScanner {

    private val logger = LoggerFactory.getLogger(ModuleScanner::class.java)

    /**
     * scan far all available icap-server modules under specified base package
     *
     * @param basePackage the base package where modules resides
     *
     * @return scanned modules under the specified package
     */
    fun scanForModules(basePackage: String): Set<ModuleMeta> {
        val modules: MutableSet<ModuleMeta> = mutableSetOf()
        // list of <endpoint to moduleClass>
        val clses: List<Pair<String, Class<Any>>> = scanForModuleClses(basePackage)
        clses.forEach { pair ->
            runCatching { modules.add(parseMeta(pair)) }.onFailure { logger.error("Module class: ${pair.second.name} parsing failed, this module will be omitted.", it) }
        }
        return modules
    }

    // list of <endpoint to moduleClass>
    private fun scanForModuleClses(pkg: String): List<Pair<String, Class<in Any>>> {
        val reflections = Reflections(ConfigurationBuilder().forPackage(pkg).filterInputsBy(FilterBuilder().includePackage(pkg)).setScanners(Scanners.TypesAnnotated))
        val moduleClses = reflections.get(Scanners.TypesAnnotated.of(Module::class.java).asClass<Any>())
        val ret: MutableList<Pair<String, Class<Any>>> = mutableListOf()
        if (!moduleClses.isNullOrEmpty()) {
            moduleClses.forEach { cls ->
                runCatching {
                    val annos = ReflectionUtils.get(ReflectionUtils.Annotations.get(cls), { it.annotationClass == Module::class })
                    annos.forEach {
                        ret.add((it as Module).value to (cls as Class<Any>))
                    }
                }.onFailure { logger.error("Module class: ${cls.name} scanning failed, this module will be omitted.", it) }
            }
        }
        return ret
    }

    private fun parseMeta(pair: Pair<String, Class<Any>>): ModuleMeta {
        return ModuleMeta(endpoint = pair.first)
        // TODO other meta props
    }

}