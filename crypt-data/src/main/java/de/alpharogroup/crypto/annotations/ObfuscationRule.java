package de.alpharogroup.crypto.annotations;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 * The interface {@link ObfuscationRule}.
 */
@Retention(RUNTIME)
@Target({ TYPE, FIELD })
public @interface ObfuscationRule {

}
