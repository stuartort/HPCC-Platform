import * as declare from "dojo/_base/declare";

/**
 * A decorator that converts a TypeScript class into a declare constructor.
 * This allows declare constructors to be defined as classes, which nicely
 * hides away the `declare([], {})` boilerplate.
 */
export function declareDecorator(classID: string, ...mixins: object[]) {
    return function (target) {
        return declare(classID, mixins, target.prototype);
    };
}

type Constructor<T = object> = new (...args: any[]) => T;
export function declareMixin<T extends Constructor>(target: T, classID: string, ...mixins: object[]): T {
    return declare(classID, mixins, target.prototype);
}
