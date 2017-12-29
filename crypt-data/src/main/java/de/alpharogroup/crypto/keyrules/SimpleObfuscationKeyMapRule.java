package de.alpharogroup.crypto.keyrules;


import lombok.*;
import lombok.experimental.FieldDefaults;

@Getter
@Setter
@EqualsAndHashCode
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder(toBuilder = true)
@FieldDefaults(level = AccessLevel.PRIVATE)
public class SimpleObfuscationKeyMapRule {

    String character;

    String replaceWith;
}
