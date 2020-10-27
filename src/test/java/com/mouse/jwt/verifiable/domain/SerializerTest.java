package com.mouse.jwt.verifiable.domain;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

class SerializerTest {

    @Test
    void shouldBeAbleToRaiseExceptionWhenNotInitialized() {
        Serializer.resetSerializer(null);

        Throwable throwable = catchThrowable(() -> {
            Serializer instance = Serializer.getInstance();
            assertThat(instance).isNull();
        });

        assertThat(throwable).isNotNull();
        assertThat(throwable).isInstanceOf(RuntimeException.class);
        assertThat(throwable).hasMessage("Serializer not initialized");
    }
}