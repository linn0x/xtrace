from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qs, urlparse


FINGERPRINT_EXPECTED_APIS = [
    "CanvasRenderingContext2D.fillText",
    "CanvasRenderingContext2D.getImageData",
    "HTMLCanvasElement.toDataURL",
    "Crypto.getRandomValues",
    "Crypto.randomUUID",
    "Navigator.platform",
    "Navigator.webdriver",
    "Navigator.cookieEnabled",
    "Screen.width",
    "Screen.height",
    "Screen.colorDepth",
    "WebGLRenderingContext.getParameter",
    "WebGLRenderingContext.getSupportedExtensions",
    "WebGLRenderingContext.getExtension",
    "WebGLRenderingContext.readPixels",
    "AudioContext.constructor",
    "OfflineAudioContext.constructor",
    "BaseAudioContext.createAnalyser",
    "BaseAudioContext.createOscillator",
    "Permissions.query",
    "MediaDevices.enumerateDevices",
    "RTCPeerConnection.constructor",
    "Intl.DateTimeFormat.constructor",
    "Intl.DateTimeFormat.resolvedOptions",
]
REVERSE_EXPECTED_APIS = [
    "fetch",
    "XMLHttpRequest.open",
    "XMLHttpRequest.setRequestHeader",
    "XMLHttpRequest.send",
    "XMLHttpRequest.responseText",
    "Storage.getItem",
    "Storage.setItem",
    "Storage.removeItem",
    "Storage.key",
    "Storage.clear",
    "Document.cookie.get",
    "Document.cookie.set",
    "Document.urlForBinding.get",
    "Document.referrer.get",
    "Node.baseURI.get",
    "CookieStore.get",
    "CookieStore.getAll",
    "CookieStore.set",
    "CookieStore.delete",
    "eval",
    "Function",
    "setTimeout.string",
    "HTMLScriptElement.src.set",
    "EventTarget.addEventListener",
    "EventTarget.removeEventListener",
    "EventTarget.dispatchEvent",
    "EventTarget.listener.invoke",
    "queueMicrotask",
    "Promise.prototype.then",
    "Promise.prototype.catch",
    "Promise.prototype.finally",
    "Promise.resolve",
    "Promise.reject",
    "Promise.all",
    "Promise.allSettled",
    "Promise.race",
    "Promise.any",
    "Promise.try",
    "Promise.withResolvers",
    "Array.fromAsync",
    "AsyncFunction.enter",
    "AsyncFunction.await",
    "AsyncFunction.resume",
    "AsyncFunction.resolve",
    "AsyncFunction.reject",
    "ClassicScript.evaluate",
    "ModuleScript.evaluate",
    "DynamicImport.resolve",
    "DynamicImport.load",
    "URLSearchParams.constructor",
    "URLSearchParams.append",
    "URLSearchParams.set",
    "URLSearchParams.delete",
    "URLSearchParams.sort",
    "URLSearchParams.toString",
    "URLSearchParams.get",
    "URLSearchParams.getAll",
    "URLSearchParams.has",
    "URLSearchParams.iterator.next",
    "URL.constructor",
    "URL.href.get",
    "URL.search.get",
    "URL.href.set",
    "URL.search.set",
    "Location.href.get",
    "Location.search.get",
    "Location.href.set",
    "Location.search.set",
    "Location.assign",
    "Location.replace",
    "Headers.constructor",
    "Headers.append",
    "Headers.set",
    "Headers.delete",
    "Headers.get",
    "Headers.has",
    "Headers.iterator.next",
    "FormData.constructor",
    "FormData.append",
    "FormData.set",
    "FormData.get",
    "FormData.getAll",
    "FormData.has",
    "FormData.delete",
    "FormData.iterator.next",
    "encodeURI",
    "encodeURIComponent",
    "decodeURI",
    "decodeURIComponent",
    "btoa",
    "atob",
    "TextEncoder.constructor",
    "TextEncoder.encode",
    "TextEncoder.encodeInto",
    "TextDecoder.constructor",
    "TextDecoder.decode",
    "JSON.parse",
    "JSON.stringify",
    "Crypto.getRandomValues",
    "Crypto.randomUUID",
    "SubtleCrypto.encrypt",
    "SubtleCrypto.decrypt",
    "SubtleCrypto.digest",
    "SubtleCrypto.importKey",
    "SubtleCrypto.sign",
    "SubtleCrypto.verify",
    "SubtleCrypto.generateKey",
    "SubtleCrypto.exportKey",
    "SubtleCrypto.deriveBits",
    "SubtleCrypto.deriveKey",
    "SubtleCrypto.wrapKey",
    "SubtleCrypto.unwrapKey",
    "ArrayBuffer.constructor",
    "ArrayBuffer.prototype.slice",
    "DataView.getInt8",
    "DataView.getInt16",
    "DataView.getUint8",
    "DataView.getUint16",
    "DataView.getUint32",
    "DataView.getInt32",
    "DataView.getBigUint64",
    "DataView.getBigInt64",
    "DataView.getFloat16",
    "DataView.getFloat32",
    "DataView.getFloat64",
    "DataView.setInt8",
    "DataView.setInt16",
    "DataView.setUint8",
    "DataView.setUint16",
    "DataView.setUint32",
    "DataView.setInt32",
    "DataView.setBigUint64",
    "DataView.setBigInt64",
    "DataView.setFloat16",
    "DataView.setFloat32",
    "DataView.setFloat64",
    "TypedArray.at",
    "TypedArray.slice",
    "TypedArray.subarray",
    "TypedArray.set",
    "TypedArray.copyWithin",
    "TypedArray.fill",
    "TypedArray.reverse",
    "TypedArray.sort",
    "TypedArray.join",
    "TypedArray.indexOf",
    "TypedArray.includes",
    "TypedArray.lastIndexOf",
    "TypedArray.find",
    "TypedArray.findIndex",
    "TypedArray.findLast",
    "TypedArray.findLastIndex",
    "TypedArray.reduce",
    "TypedArray.reduceRight",
    "TypedArray.filter",
    "TypedArray.every",
    "TypedArray.some",
    "TypedArray.forEach",
    "TypedArray.entries",
    "TypedArray.keys",
    "TypedArray.values",
    "Array.from",
    "Array.of",
    "Array.prototype.at",
    "Array.prototype.indexOf",
    "Array.prototype.includes",
    "Array.prototype.lastIndexOf",
    "Array.prototype.find",
    "Array.prototype.findIndex",
    "Array.prototype.findLast",
    "Array.prototype.findLastIndex",
    "Array.prototype.reduce",
    "Array.prototype.reduceRight",
    "Array.prototype.map",
    "Array.prototype.filter",
    "Array.prototype.flat",
    "Array.prototype.flatMap",
    "Array.prototype.every",
    "Array.prototype.some",
    "Array.prototype.forEach",
    "Array.prototype.push",
    "Array.prototype.pop",
    "Array.prototype.unshift",
    "Array.prototype.shift",
    "Array.prototype.splice",
    "Array.prototype.reverse",
    "Array.prototype.sort",
    "Array.prototype.copyWithin",
    "Array.prototype.fill",
    "Array.prototype.slice",
    "Array.prototype.join",
    "Array.prototype.entries",
    "Array.prototype.keys",
    "Array.prototype.values",
    "ArrayIterator.prototype.next",
    "Generator.prototype.next",
    "Generator.prototype.return",
    "Generator.prototype.throw",
    "AsyncGenerator.prototype.next",
    "AsyncGenerator.prototype.return",
    "AsyncGenerator.prototype.throw",
    "Reflect.apply",
    "Reflect.construct",
    "Function.prototype.call",
    "Function.prototype.apply",
    "Object.keys",
    "Object.prototype.toString",
    "Array.isArray",
    "Object.is",
    "Object.hasOwn",
    "Object.prototype.hasOwnProperty",
    "Object.prototype.propertyIsEnumerable",
    "Object.assign",
    "Object.create",
    "Object.getPrototypeOf",
    "Object.setPrototypeOf",
    "Object.getOwnPropertyDescriptor",
    "Object.getOwnPropertyDescriptors",
    "Object.defineProperty",
    "Object.defineProperties",
    "Object.preventExtensions",
    "Object.freeze",
    "Object.seal",
    "Object.isExtensible",
    "Object.isFrozen",
    "Object.isSealed",
    "Object.values",
    "Object.entries",
    "Object.getOwnPropertyNames",
    "Reflect.getPrototypeOf",
    "Reflect.setPrototypeOf",
    "Reflect.defineProperty",
    "Reflect.preventExtensions",
    "Reflect.isExtensible",
    "Reflect.ownKeys",
    "Reflect.getOwnPropertyDescriptor",
    "Reflect.get",
    "Reflect.set",
    "Reflect.has",
    "Reflect.deleteProperty",
    "Map.prototype.get",
    "Map.prototype.has",
    "Map.prototype.set",
    "Map.prototype.delete",
    "Map.prototype.clear",
    "Map.prototype.getOrInsert",
    "Map.prototype.getOrInsertComputed",
    "Map.prototype.forEach",
    "Map.prototype.entries",
    "Map.prototype.keys",
    "Map.prototype.values",
    "Set.prototype.add",
    "Set.prototype.has",
    "Set.prototype.delete",
    "Set.prototype.clear",
    "Set.prototype.forEach",
    "Set.prototype.entries",
    "Set.prototype.values",
    "MapIterator.prototype.next",
    "SetIterator.prototype.next",
    "WeakMap.prototype.get",
    "WeakMap.prototype.has",
    "WeakMap.prototype.set",
    "WeakMap.prototype.delete",
    "WeakMap.prototype.getOrInsert",
    "WeakMap.prototype.getOrInsertComputed",
    "WeakSet.prototype.add",
    "WeakSet.prototype.has",
    "WeakSet.prototype.delete",
    "Proxy.get",
    "Proxy.set",
    "Proxy.has",
    "Proxy.ownKeys",
    "Proxy.getOwnPropertyDescriptor",
    "Proxy.defineProperty",
    "Proxy.deleteProperty",
    "String.fromCharCode",
    "String.fromCodePoint",
    "String.prototype.charCodeAt",
    "String.prototype.codePointAt",
    "String.prototype.charAt",
    "String.prototype.at",
    "String.prototype.concat",
    "StringAdd",
    "StringAdd.constant_lhs",
    "StringAdd.constant_rhs",
    "String.prototype.slice",
    "String.prototype.substring",
    "String.prototype.substr",
    "String.prototype.padStart",
    "String.prototype.padEnd",
    "String.prototype.repeat",
    "String.prototype.startsWith",
    "String.prototype.endsWith",
    "String.prototype.trim",
    "String.prototype.trimStart",
    "String.prototype.trimEnd",
    "String.prototype.@@iterator",
    "StringIterator.prototype.next",
    "Number.prototype.toString",
    "BigInt.prototype.toString",
    "Number.parseInt",
    "Number.parseFloat",
    "String.prototype.indexOf",
    "String.prototype.lastIndexOf",
    "String.prototype.includes",
    "String.prototype.replace",
    "String.prototype.replaceAll",
    "String.prototype.split",
    "String.prototype.search",
    "String.prototype.match",
    "String.prototype.matchAll",
    "String.prototype.toLowerCase",
    "String.prototype.toUpperCase",
    "RegExp.prototype.test",
    "RegExp.prototype.exec",
    "RegExp.prototype.@@search",
    "RegExp.prototype.@@match",
    "RegExp.prototype.@@matchAll",
    "RegExp.prototype.@@split",
    "RegExp.prototype.@@replace",
    "RegExpStringIterator.prototype.next",
    "Math.imul",
    "Bitwise.and",
    "Bitwise.or",
    "Bitwise.xor",
    "Bitwise.not",
    "Shift.left",
    "Shift.right",
    "Shift.unsignedRight",
    "Math.random",
    "Performance.now",
    "Date.now",
    "console.debug",
    "console.clear",
    "debugger.statement",
    "Function.prototype.toString",
    "Error.captureStackTrace",
    "Error.stack.get",
    "Error.constructor",
    "Exception.throw",
    "Request.constructor",
    "Request.method.get",
    "Request.url.get",
    "Request.headers.get",
    "Request.clone",
    "Response.type.get",
    "Response.url.get",
    "Response.redirected.get",
    "Response.status.get",
    "Response.ok.get",
    "Response.statusText.get",
    "Response.headers.get",
    "Response.clone",
    "Body.text",
    "Body.json",
    "Body.arrayBuffer",
]
BUSINESS_API_EXPECTED_APIS = [
    "Navigator.language",
    "URLSearchParams.set",
    "URLSearchParams.toString",
    "URL.search.set",
    "URL.href.get",
    "Headers.set",
    "Headers.append",
    "Request.constructor",
    "Request.headers.get",
    "Request.url.get",
    "fetch",
    "Response.status.get",
    "Response.url.get",
    "Response.headers.get",
    "XMLHttpRequest.open",
    "XMLHttpRequest.setRequestHeader",
    "XMLHttpRequest.send",
    "XMLHttpRequest.responseText",
    "BrowserNetwork.request",
]
DEFAULT_EXPECTED_APIS = FINGERPRINT_EXPECTED_APIS
PROFILE_EXPECTED_APIS = {
    "business-api": BUSINESS_API_EXPECTED_APIS,
    "fingerprint": FINGERPRINT_EXPECTED_APIS,
    "generic-vmp": [],
    "reverse": REVERSE_EXPECTED_APIS,
    "all": [*FINGERPRINT_EXPECTED_APIS, *REVERSE_EXPECTED_APIS],
}
BUSINESS_API_ENDPOINT_PATH = "/api/recommend/item_list/"
BUSINESS_API_REQUIRED_GET_QUERY_KEYS = {
    "client_time",
    "app_id",
    "app_name",
    "browser_language",
    "browser_platform",
    "count",
    "device_platform",
    "screen_height",
    "screen_width",
    "source",
    "sessionToken",
    "X-Signature",
}
BUSINESS_API_REQUIRED_XHR_QUERY_KEYS = {"transport", "cursor", "X-Signature"}
BUSINESS_API_REQUIRED_FETCH_HEADER_NAMES = {"x-xtrace-smoke", "x-session-token", "x-signature"}
BUSINESS_API_REQUIRED_XHR_HEADER_NAMES = {"content-type", "x-xtrace-smoke"}
BUSINESS_API_REQUIRED_RESPONSE_HEADER_NAMES = {"content-type"}
BUSINESS_API_REQUIRED_BROWSER_HEADER_NAMES = {
    "accept",
    "accept-language",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "user-agent",
}


def expected_apis_for_profile(profile: str | None, explicit_expected: Iterable[str]) -> list[str]:
    expected: list[str] = []
    seen: set[str] = set()
    profile_expected = PROFILE_EXPECTED_APIS[profile] if profile is not None else []
    for api in [*profile_expected, *explicit_expected]:
        if api in seen:
            continue
        expected.append(api)
        seen.add(api)
    return expected


def merge_required_values(*groups: Iterable[str]) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for group in groups:
        for value in group:
            if value in seen:
                continue
            merged.append(value)
            seen.add(value)
    return merged


VMP_API_FAMILY = {
    "btoa": "base64",
    "atob": "base64",
    "encodeURI": "url_encoding",
    "encodeURIComponent": "url_encoding",
    "decodeURI": "url_encoding",
    "decodeURIComponent": "url_encoding",
    "URLSearchParams.toString": "url_encoding",
    "TextEncoder.constructor": "text_codec",
    "TextEncoder.encode": "text_codec",
    "TextEncoder.encodeInto": "text_codec",
    "TextDecoder.constructor": "text_codec",
    "TextDecoder.decode": "text_codec",
    "JSON.parse": "json_serialization",
    "JSON.stringify": "json_serialization",
    "SubtleCrypto.encrypt": "hash_crypto",
    "SubtleCrypto.decrypt": "hash_crypto",
    "SubtleCrypto.digest": "hash_crypto",
    "SubtleCrypto.importKey": "hash_crypto",
    "SubtleCrypto.sign": "hash_crypto",
    "SubtleCrypto.verify": "hash_crypto",
    "SubtleCrypto.generateKey": "hash_crypto",
    "SubtleCrypto.exportKey": "hash_crypto",
    "SubtleCrypto.deriveBits": "hash_crypto",
    "SubtleCrypto.deriveKey": "hash_crypto",
    "SubtleCrypto.wrapKey": "hash_crypto",
    "SubtleCrypto.unwrapKey": "hash_crypto",
    "Crypto.getRandomValues": "random_source",
    "Crypto.randomUUID": "random_source",
    "ArrayBuffer.constructor": "byte_buffer",
    "ArrayBuffer.prototype.slice": "byte_buffer",
    "DataView.getInt8": "byte_buffer",
    "DataView.getInt16": "byte_buffer",
    "DataView.getUint8": "byte_buffer",
    "DataView.getUint16": "byte_buffer",
    "DataView.getUint32": "byte_buffer",
    "DataView.getInt32": "byte_buffer",
    "DataView.getBigUint64": "byte_buffer",
    "DataView.getBigInt64": "byte_buffer",
    "DataView.getFloat16": "byte_buffer",
    "DataView.getFloat32": "byte_buffer",
    "DataView.getFloat64": "byte_buffer",
    "DataView.setInt8": "byte_buffer",
    "DataView.setInt16": "byte_buffer",
    "DataView.setUint8": "byte_buffer",
    "DataView.setUint16": "byte_buffer",
    "DataView.setUint32": "byte_buffer",
    "DataView.setInt32": "byte_buffer",
    "DataView.setBigUint64": "byte_buffer",
    "DataView.setBigInt64": "byte_buffer",
    "DataView.setFloat16": "byte_buffer",
    "DataView.setFloat32": "byte_buffer",
    "DataView.setFloat64": "byte_buffer",
    "TypedArray.at": "typed_array",
    "TypedArray.slice": "typed_array",
    "TypedArray.subarray": "typed_array",
    "TypedArray.set": "typed_array",
    "TypedArray.copyWithin": "typed_array",
    "TypedArray.fill": "typed_array",
    "TypedArray.reverse": "typed_array",
    "TypedArray.sort": "typed_array",
    "TypedArray.join": "typed_array",
    "TypedArray.indexOf": "typed_array",
    "TypedArray.includes": "typed_array",
    "TypedArray.lastIndexOf": "typed_array",
    "TypedArray.find": "typed_array",
    "TypedArray.findIndex": "typed_array",
    "TypedArray.findLast": "typed_array",
    "TypedArray.findLastIndex": "typed_array",
    "TypedArray.reduce": "typed_array",
    "TypedArray.reduceRight": "typed_array",
    "TypedArray.filter": "typed_array",
    "TypedArray.every": "typed_array",
    "TypedArray.some": "typed_array",
    "TypedArray.forEach": "typed_array",
    "TypedArray.entries": "sequence_iterator",
    "TypedArray.keys": "sequence_iterator",
    "TypedArray.values": "sequence_iterator",
    "Array.from": "array_table",
    "Array.of": "array_table",
    "Array.prototype.at": "array_table",
    "Array.prototype.indexOf": "array_table",
    "Array.prototype.includes": "array_table",
    "Array.prototype.lastIndexOf": "array_table",
    "Array.prototype.find": "array_table",
    "Array.prototype.findIndex": "array_table",
    "Array.prototype.findLast": "array_table",
    "Array.prototype.findLastIndex": "array_table",
    "Array.prototype.reduce": "array_table",
    "Array.prototype.reduceRight": "array_table",
    "Array.prototype.map": "array_table",
    "Array.prototype.filter": "array_table",
    "Array.prototype.flat": "array_table",
    "Array.prototype.flatMap": "array_table",
    "Array.prototype.every": "array_table",
    "Array.prototype.some": "array_table",
    "Array.prototype.forEach": "array_table",
    "Array.prototype.push": "array_table",
    "Array.prototype.pop": "array_table",
    "Array.prototype.unshift": "array_table",
    "Array.prototype.splice": "array_table",
    "Array.prototype.reverse": "array_table",
    "Array.prototype.sort": "array_table",
    "Array.prototype.copyWithin": "array_table",
    "Array.prototype.fill": "array_table",
    "Array.prototype.slice": "array_table",
    "Array.prototype.join": "array_table",
    "Array.prototype.entries": "sequence_iterator",
    "Array.prototype.keys": "sequence_iterator",
    "Array.prototype.values": "sequence_iterator",
    "ArrayIterator.prototype.next": "sequence_iterator",
    "Generator.prototype.next": "generator_state",
    "Generator.prototype.return": "generator_state",
    "Generator.prototype.throw": "generator_state",
    "AsyncGenerator.prototype.next": "generator_state",
    "AsyncGenerator.prototype.return": "generator_state",
    "AsyncGenerator.prototype.throw": "generator_state",
    "Array.prototype.shift": "array_table",
    "Reflect.apply": "dynamic_dispatch",
    "Reflect.apply.call": "dynamic_dispatch",
    "Reflect.construct": "dynamic_dispatch",
    "Reflect.ownKeys": "dynamic_dispatch",
    "Reflect.getOwnPropertyDescriptor": "dynamic_dispatch",
    "Reflect.get": "dynamic_dispatch",
    "Reflect.set": "dynamic_dispatch",
    "Reflect.has": "dynamic_dispatch",
    "Reflect.deleteProperty": "dynamic_dispatch",
    "Function.prototype.call": "dynamic_dispatch",
    "Function.prototype.call.call": "dynamic_dispatch",
    "Function.prototype.apply": "dynamic_dispatch",
    "Function.prototype.apply.call": "dynamic_dispatch",
    "Promise.prototype.then": "async_flow",
    "Promise.prototype.catch": "async_flow",
    "Promise.prototype.finally": "async_flow",
    "Promise.resolve": "async_flow",
    "Promise.reject": "async_flow",
    "Promise.all": "async_flow",
    "Promise.allSettled": "async_flow",
    "Promise.race": "async_flow",
    "Promise.any": "async_flow",
    "Promise.try": "async_flow",
    "Promise.withResolvers": "async_flow",
    "Array.fromAsync": "async_flow",
    "AsyncFunction.enter": "async_flow",
    "AsyncFunction.await": "async_flow",
    "AsyncFunction.resume": "async_flow",
    "AsyncFunction.resolve": "async_flow",
    "AsyncFunction.reject": "async_flow",
    "ClassicScript.evaluate": "script_execution",
    "ModuleScript.evaluate": "script_execution",
    "DynamicImport.resolve": "script_execution",
    "DynamicImport.load": "script_execution",
    "Object.keys": "dynamic_dispatch",
    "Object.prototype.toString": "dynamic_dispatch",
    "Array.isArray": "dynamic_dispatch",
    "Object.is": "dynamic_dispatch",
    "Object.hasOwn": "dynamic_dispatch",
    "Object.prototype.hasOwnProperty": "dynamic_dispatch",
    "Object.prototype.propertyIsEnumerable": "dynamic_dispatch",
    "Object.assign": "dynamic_dispatch",
    "Object.create": "dynamic_dispatch",
    "Object.getPrototypeOf": "dynamic_dispatch",
    "Object.setPrototypeOf": "dynamic_dispatch",
    "Object.getOwnPropertyDescriptor": "dynamic_dispatch",
    "Object.getOwnPropertyDescriptors": "dynamic_dispatch",
    "Object.defineProperty": "dynamic_dispatch",
    "Object.defineProperties": "dynamic_dispatch",
    "Object.preventExtensions": "dynamic_dispatch",
    "Object.freeze": "dynamic_dispatch",
    "Object.seal": "dynamic_dispatch",
    "Object.isExtensible": "dynamic_dispatch",
    "Object.isFrozen": "dynamic_dispatch",
    "Object.isSealed": "dynamic_dispatch",
    "Object.values": "dynamic_dispatch",
    "Object.entries": "dynamic_dispatch",
    "Object.getOwnPropertyNames": "dynamic_dispatch",
    "Reflect.getPrototypeOf": "dynamic_dispatch",
    "Reflect.setPrototypeOf": "dynamic_dispatch",
    "Reflect.defineProperty": "dynamic_dispatch",
    "Reflect.preventExtensions": "dynamic_dispatch",
    "Reflect.isExtensible": "dynamic_dispatch",
    "Map.prototype.get": "collection_table",
    "Map.prototype.has": "collection_table",
    "Map.prototype.set": "collection_table",
    "Map.prototype.delete": "collection_table",
    "Map.prototype.clear": "collection_table",
    "Map.prototype.getOrInsert": "collection_table",
    "Map.prototype.getOrInsertComputed": "collection_table",
    "Map.prototype.forEach": "collection_table",
    "Map.prototype.entries": "collection_table",
    "Map.prototype.keys": "collection_table",
    "Map.prototype.values": "collection_table",
    "Set.prototype.add": "collection_table",
    "Set.prototype.has": "collection_table",
    "Set.prototype.delete": "collection_table",
    "Set.prototype.clear": "collection_table",
    "Set.prototype.forEach": "collection_table",
    "Set.prototype.entries": "collection_table",
    "Set.prototype.values": "collection_table",
    "MapIterator.prototype.next": "collection_table",
    "SetIterator.prototype.next": "collection_table",
    "WeakMap.prototype.get": "collection_table",
    "WeakMap.prototype.has": "collection_table",
    "WeakMap.prototype.set": "collection_table",
    "WeakMap.prototype.delete": "collection_table",
    "WeakMap.prototype.getOrInsert": "collection_table",
    "WeakMap.prototype.getOrInsertComputed": "collection_table",
    "WeakSet.prototype.add": "collection_table",
    "WeakSet.prototype.has": "collection_table",
    "WeakSet.prototype.delete": "collection_table",
    "Proxy.get": "proxy_trap",
    "Proxy.set": "proxy_trap",
    "Proxy.has": "proxy_trap",
    "Proxy.ownKeys": "proxy_trap",
    "Proxy.getOwnPropertyDescriptor": "proxy_trap",
    "Proxy.defineProperty": "proxy_trap",
    "Proxy.deleteProperty": "proxy_trap",
    "Bitwise.and": "int_bitwise",
    "Bitwise.or": "int_bitwise",
    "Bitwise.xor": "int_bitwise",
    "Bitwise.not": "int_bitwise",
    "Shift.left": "int_bitwise",
    "Shift.right": "int_bitwise",
    "Shift.unsignedRight": "int_bitwise",
    "String.fromCharCode": "string_decode",
    "String.fromCodePoint": "string_decode",
    "String.prototype.charCodeAt": "string_decode",
    "String.prototype.codePointAt": "string_decode",
    "String.prototype.charAt": "string_decode",
    "String.prototype.at": "string_decode",
    "String.prototype.concat": "string_transform",
    "StringAdd": "string_transform",
    "StringAdd.constant_lhs": "string_transform",
    "StringAdd.constant_rhs": "string_transform",
    "String.prototype.slice": "string_transform",
    "String.prototype.substring": "string_transform",
    "String.prototype.substr": "string_transform",
    "String.prototype.padStart": "string_transform",
    "String.prototype.padEnd": "string_transform",
    "String.prototype.repeat": "string_transform",
    "String.prototype.startsWith": "string_transform",
    "String.prototype.endsWith": "string_transform",
    "String.prototype.trim": "string_transform",
    "String.prototype.trimStart": "string_transform",
    "String.prototype.trimEnd": "string_transform",
    "String.prototype.@@iterator": "sequence_iterator",
    "StringIterator.prototype.next": "sequence_iterator",
    "Number.prototype.toString": "string_transform",
    "BigInt.prototype.toString": "string_transform",
    "Number.parseInt": "number_parse",
    "Number.parseFloat": "number_parse",
    "String.prototype.indexOf": "string_transform",
    "String.prototype.lastIndexOf": "string_transform",
    "String.prototype.includes": "string_transform",
    "String.prototype.replace": "string_transform",
    "String.prototype.replaceAll": "string_transform",
    "String.prototype.split": "string_transform",
    "String.prototype.search": "regexp_probe",
    "String.prototype.match": "regexp_probe",
    "String.prototype.matchAll": "regexp_probe",
    "String.prototype.toLowerCase": "string_transform",
    "String.prototype.toUpperCase": "string_transform",
    "RegExp.prototype.test": "regexp_probe",
    "RegExp.prototype.exec": "regexp_probe",
    "RegExp.prototype.@@search": "regexp_probe",
    "RegExp.prototype.@@match": "regexp_probe",
    "RegExp.prototype.@@matchAll": "regexp_probe",
    "RegExp.prototype.@@split": "regexp_probe",
    "RegExp.prototype.@@replace": "regexp_probe",
    "RegExpStringIterator.prototype.next": "regexp_probe",
    "Math.imul": "int_arithmetic",
    "Math.random": "random_source",
    "Performance.now": "anti_debug_timing",
    "Date.now": "anti_debug_timing",
    "console.debug": "anti_debug_timing",
    "console.clear": "anti_debug_timing",
    "debugger.statement": "anti_debug_timing",
    "Function.prototype.toString": "source_probe",
    "Error.captureStackTrace": "stack_probe",
    "Error.stack.get": "stack_probe",
    "Error.constructor": "exception_probe",
    "Exception.throw": "exception_probe",
}
VMP_FAMILIES = sorted(set(VMP_API_FAMILY.values()))
STRICT_CAPTURE_VMP_FAMILIES = VMP_FAMILIES
STRICT_CAPTURE_PROFILE_SIGNATURE_PARAMS = {
    "business-api": ["X-Signature"],
}
VMP_NEXT_HOOK_REQUIRED_ARG_FIELDS = [
    "String.fromCharCode:result_ref",
    "String.prototype.slice:subject_ref",
    "String.prototype.slice:result_ref",
    "encodeURIComponent:input_ref",
    "encodeURIComponent:result_ref",
    "Bitwise.xor:result_ref",
    "BigInt.prototype.toString:result_ref",
    "URLSearchParams.set:search_params_id",
    "URLSearchParams.set:url_object_id",
    "URLSearchParams.set:name",
    "URLSearchParams.set:name_length",
    "URLSearchParams.set:name_ref",
    "URLSearchParams.set:value",
    "URLSearchParams.set:value_length",
    "URLSearchParams.set:value_ref",
    "URLSearchParams.set:replaced_existing",
    "URLSearchParams.set:before_serialized",
    "URLSearchParams.set:before_serialized_length",
    "URLSearchParams.set:before_serialized_ref",
    "URLSearchParams.set:serialized",
    "URLSearchParams.set:serialized_length",
    "URLSearchParams.set:serialized_ref",
    "URLSearchParams.toString:search_params_id",
    "URLSearchParams.toString:url_object_id",
    "URLSearchParams.toString:size",
    "URLSearchParams.toString:serialized",
    "URLSearchParams.toString:serialized_length",
    "URLSearchParams.toString:serialized_ref",
    "URLSearchParams.toString:result_ref",
    "URL.href.set:value_ref",
    "URL.href.set:href_ref",
    "URL.search.set:value_ref",
    "URL.search.set:search_ref",
    "URL.search.set:href_ref",
    "Location.href.get:result_length",
    "Location.href.get:result_ref",
    "Location.search.get:result_length",
    "Location.search.get:result_ref",
    "Location.search.get:href_length",
    "Location.search.get:href_ref",
    "Location.href.set:value_length",
    "Location.href.set:value_ref",
    "Location.href.set:href_length",
    "Location.href.set:href_ref",
    "Location.search.set:value_length",
    "Location.search.set:value_ref",
    "Location.search.set:href_length",
    "Location.search.set:href_ref",
    "Location.assign:value_length",
    "Location.assign:value_ref",
    "Location.assign:href_length",
    "Location.assign:href_ref",
    "Location.replace:value_length",
    "Location.replace:value_ref",
    "Location.replace:href_length",
    "Location.replace:href_ref",
    "Storage.getItem:key",
    "Storage.getItem:key_length",
    "Storage.getItem:key_ref",
    "Storage.setItem:key",
    "Storage.setItem:key_length",
    "Storage.setItem:key_ref",
    "Storage.setItem:value",
    "Storage.setItem:value_length",
    "Storage.setItem:value_ref",
    "Storage.removeItem:key",
    "Storage.removeItem:key_length",
    "Storage.removeItem:key_ref",
    "Document.cookie.get:value_length",
    "Document.cookie.get:value_ref",
    "Document.cookie.set:value_length",
    "Document.cookie.set:value_ref",
    "Document.cookie.set:accepted",
    "Document.urlForBinding.get:result_length",
    "Document.urlForBinding.get:result_ref",
    "Document.referrer.get:result_length",
    "Document.referrer.get:result_ref",
    "Node.baseURI.get:result_length",
    "Node.baseURI.get:result_ref",
    "CookieStore.get:cookie_url_ref",
    "CookieStore.get:result_count",
    "CookieStore.get:result_names",
    "CookieStore.get:result_name_lengths",
    "CookieStore.get:result_name_refs",
    "CookieStore.get:result_values",
    "CookieStore.get:result_value_lengths",
    "CookieStore.get:result_value_refs",
    "CookieStore.getAll:cookie_url_ref",
    "CookieStore.getAll:result_count",
    "CookieStore.getAll:result_names",
    "CookieStore.getAll:result_name_lengths",
    "CookieStore.getAll:result_name_refs",
    "CookieStore.getAll:result_values",
    "CookieStore.getAll:result_value_lengths",
    "CookieStore.getAll:result_value_refs",
    "CookieStore.set:name_length",
    "CookieStore.set:name_ref",
    "CookieStore.set:value_length",
    "CookieStore.set:value_ref",
    "CookieStore.set:cookie_url_ref",
    "CookieStore.set:accepted",
    "CookieStore.delete:name_length",
    "CookieStore.delete:name_ref",
    "CookieStore.delete:cookie_url_ref",
    "CookieStore.delete:accepted",
]
VMP_NEXT_HOOK_REQUIRED_OBSERVED_ARG_FIELDS = [
    "btoa:input_hex",
    "btoa:input_ref",
    "btoa:result_hex",
    "btoa:result_ref",
    "atob:input_hex",
    "atob:input_ref",
    "atob:result_hex",
    "atob:result_ref",
    "encodeURI:input",
    "encodeURI:input_ref",
    "encodeURI:input_length",
    "encodeURI:result",
    "encodeURI:result_ref",
    "encodeURI:result_length",
    "encodeURIComponent:input",
    "encodeURIComponent:input_ref",
    "encodeURIComponent:input_length",
    "encodeURIComponent:result",
    "encodeURIComponent:result_ref",
    "encodeURIComponent:result_length",
    "decodeURI:input",
    "decodeURI:input_ref",
    "decodeURI:input_length",
    "decodeURI:result",
    "decodeURI:result_ref",
    "decodeURI:result_length",
    "decodeURIComponent:input",
    "decodeURIComponent:input_ref",
    "decodeURIComponent:input_length",
    "decodeURIComponent:result",
    "decodeURIComponent:result_ref",
    "decodeURIComponent:result_length",
    "Location.href.get:result",
    "Location.search.get:result",
    "Location.search.get:href",
    "Location.href.set:value",
    "Location.href.set:href",
    "Location.search.set:value",
    "Location.search.set:href",
    "Location.assign:value",
    "Location.assign:href",
    "Location.replace:value",
    "Location.replace:href",
    "String.prototype.charCodeAt:subject_ref",
    "String.prototype.charCodeAt:result_ref",
    "String.prototype.codePointAt:subject_ref",
    "String.prototype.codePointAt:result_ref",
    "String.prototype.at:subject_ref",
    "String.prototype.at:result_ref",
    "String.prototype.lastIndexOf:subject_ref",
    "String.prototype.lastIndexOf:search_ref",
    "String.prototype.lastIndexOf:result_ref",
    "String.prototype.substring:subject_ref",
    "String.prototype.substring:result_ref",
    "String.prototype.substr:subject_ref",
    "String.prototype.substr:result_ref",
    "String.prototype.concat:result_ref",
    "String.prototype.replace:subject_ref",
    "String.prototype.replace:result_ref",
    "String.prototype.split:subject_ref",
    "String.prototype.split:result_ref",
    "String.prototype.padStart:subject_ref",
    "String.prototype.padStart:result_ref",
    "String.prototype.padEnd:subject_ref",
    "String.prototype.padEnd:result_ref",
    "String.prototype.repeat:subject_ref",
    "String.prototype.repeat:repeat_count_ref",
    "String.prototype.repeat:result_ref",
    "String.prototype.search:input_ref",
    "String.prototype.search:result_ref",
    "String.prototype.match:input_ref",
    "String.prototype.match:result_ref",
    "String.prototype.matchAll:input_ref",
    "String.prototype.matchAll:regexp_ref",
    "String.prototype.matchAll:iterator_ref",
    "String.prototype.matchAll:result_ref",
    "RegExp.prototype.@@matchAll:input_ref",
    "RegExp.prototype.@@matchAll:regexp_ref",
    "RegExp.prototype.@@matchAll:iterator_ref",
    "RegExp.prototype.@@matchAll:result_ref",
    "RegExpStringIterator.prototype.next:iterator_ref",
    "RegExpStringIterator.prototype.next:regexp_ref",
    "RegExpStringIterator.prototype.next:input_ref",
    "RegExpStringIterator.prototype.next:result_ref",
    "RegExpStringIterator.prototype.next:done",
    "String.prototype.toLowerCase:subject_ref",
    "String.prototype.toLowerCase:result_ref",
    "String.prototype.toUpperCase:subject_ref",
    "String.prototype.toUpperCase:result_ref",
    "Number.prototype.toString:input_ref",
    "Number.prototype.toString:result_ref",
    "Number.parseInt:input_ref",
    "Number.parseInt:radix_ref",
    "Number.parseInt:result_ref",
    "Number.parseFloat:input_ref",
    "Number.parseFloat:result_ref",
    "TextEncoder.encode:input_ref",
    "TextEncoder.encode:result_hex",
    "TextEncoder.encode:result_ref",
    "TextEncoder.encode:result_typed_array_id",
    "TextEncoder.encode:result_array_buffer_id",
    "TextEncoder.encode:result_byte_length",
    "TextEncoder.encodeInto:input_ref",
    "TextEncoder.encodeInto:destination_typed_array_id",
    "TextEncoder.encodeInto:destination_array_buffer_id",
    "TextEncoder.encodeInto:destination_byte_length",
    "TextEncoder.encodeInto:read",
    "TextEncoder.encodeInto:written",
    "TextEncoder.encodeInto:written_hex",
    "TextEncoder.encodeInto:written_ref",
    "TextEncoder.encodeInto:destination_hex",
    "TextEncoder.encodeInto:destination_ref",
    "TextDecoder.decode:input_hex",
    "TextDecoder.decode:input_ref",
    "TextDecoder.decode:result",
    "TextDecoder.decode:result_ref",
    "JSON.parse:source",
    "JSON.parse:source_length",
    "JSON.parse:source_ref",
    "JSON.parse:reviver_type",
    "JSON.parse:reviver_ref",
    "JSON.parse:result_type",
    "JSON.parse:result_ref",
    "JSON.stringify:input_type",
    "JSON.stringify:input_ref",
    "JSON.stringify:replacer_type",
    "JSON.stringify:replacer_ref",
    "JSON.stringify:space_type",
    "JSON.stringify:space_ref",
    "JSON.stringify:result_type",
    "JSON.stringify:result",
    "JSON.stringify:result_length",
    "JSON.stringify:result_ref",
    "Array.from:source_ref",
    "Array.from:mapfn_ref",
    "Array.from:this_arg_ref",
    "Array.from:result_ref",
    "Array.from:result_element_refs",
    "Array.from:result_elements_complete",
    "Array.of:arg_count",
    "Array.of:result_ref",
    "Array.of:result_element_refs",
    "Array.of:result_elements_complete",
    "Array.fromAsync:source_ref",
    "Array.fromAsync:mapfn_ref",
    "Array.fromAsync:this_arg_ref",
    "Array.fromAsync:promise_ref",
    "Array.fromAsync:result_ref",
    "Array.fromAsync:result_element_refs",
    "Array.fromAsync:result_elements_complete",
    "Array.fromAsync:async_mode",
    "Promise.resolve:input_ref",
    "Promise.resolve:result_promise_ref",
    "Promise.reject:reason_ref",
    "Promise.reject:result_promise_ref",
    "Promise.all:iterable_ref",
    "Promise.all:result_promise_ref",
    "Promise.all:combinator",
    "Promise.allSettled:iterable_ref",
    "Promise.allSettled:result_promise_ref",
    "Promise.allSettled:combinator",
    "Promise.race:iterable_ref",
    "Promise.race:result_promise_ref",
    "Promise.race:combinator",
    "Promise.any:iterable_ref",
    "Promise.any:result_promise_ref",
    "Promise.any:combinator",
    "Promise.try:callback_ref",
    "Promise.try:result_promise_ref",
    "Promise.try:completion_state",
    "Promise.try:completion_ref",
    "Promise.withResolvers:promise_ref",
    "Promise.withResolvers:resolve_ref",
    "Promise.withResolvers:reject_ref",
    "Promise.withResolvers:result_ref",
    "SubtleCrypto.encrypt:algorithm",
    "SubtleCrypto.encrypt:key_ref",
    "SubtleCrypto.encrypt:input_ref",
    "SubtleCrypto.encrypt:input_hex",
    "SubtleCrypto.encrypt:result_ref",
    "SubtleCrypto.encrypt:result_hex",
    "SubtleCrypto.decrypt:algorithm",
    "SubtleCrypto.decrypt:key_ref",
    "SubtleCrypto.decrypt:input_ref",
    "SubtleCrypto.decrypt:input_hex",
    "SubtleCrypto.decrypt:result_ref",
    "SubtleCrypto.decrypt:result_hex",
    "SubtleCrypto.digest:algorithm",
    "SubtleCrypto.digest:input_ref",
    "SubtleCrypto.digest:input_hex",
    "SubtleCrypto.digest:result_ref",
    "SubtleCrypto.digest:result_hex",
    "SubtleCrypto.importKey:algorithm",
    "SubtleCrypto.importKey:key_data_ref",
    "SubtleCrypto.importKey:key_data_hex",
    "SubtleCrypto.importKey:key_ref",
    "SubtleCrypto.sign:algorithm",
    "SubtleCrypto.sign:key_ref",
    "SubtleCrypto.sign:input_ref",
    "SubtleCrypto.sign:input_hex",
    "SubtleCrypto.sign:result_ref",
    "SubtleCrypto.sign:result_hex",
    "SubtleCrypto.verify:algorithm",
    "SubtleCrypto.verify:key_ref",
    "SubtleCrypto.verify:signature_ref",
    "SubtleCrypto.verify:signature_hex",
    "SubtleCrypto.verify:input_ref",
    "SubtleCrypto.verify:input_hex",
    "SubtleCrypto.verify:result_ref",
    "SubtleCrypto.generateKey:algorithm",
    "SubtleCrypto.generateKey:extractable",
    "SubtleCrypto.generateKey:key_usages_mask",
    "SubtleCrypto.generateKey:result_type",
    "SubtleCrypto.exportKey:format",
    "SubtleCrypto.exportKey:key_ref",
    "SubtleCrypto.exportKey:key_algorithm",
    "SubtleCrypto.exportKey:key_type",
    "SubtleCrypto.exportKey:result_ref",
    "SubtleCrypto.deriveBits:algorithm",
    "SubtleCrypto.deriveBits:base_key_ref",
    "SubtleCrypto.deriveBits:length_bits",
    "SubtleCrypto.deriveBits:result_ref",
    "SubtleCrypto.deriveBits:result_hex",
    "SubtleCrypto.deriveKey:algorithm",
    "SubtleCrypto.deriveKey:base_key_ref",
    "SubtleCrypto.deriveKey:derived_key_algorithm",
    "SubtleCrypto.deriveKey:extractable",
    "SubtleCrypto.deriveKey:key_usages_mask",
    "SubtleCrypto.deriveKey:key_ref",
    "SubtleCrypto.wrapKey:format",
    "SubtleCrypto.wrapKey:key_ref",
    "SubtleCrypto.wrapKey:wrapping_key_ref",
    "SubtleCrypto.wrapKey:wrap_algorithm",
    "SubtleCrypto.wrapKey:result_ref",
    "SubtleCrypto.wrapKey:result_hex",
    "SubtleCrypto.unwrapKey:format",
    "SubtleCrypto.unwrapKey:unwrapping_key_ref",
    "SubtleCrypto.unwrapKey:unwrap_algorithm",
    "SubtleCrypto.unwrapKey:unwrapped_key_algorithm",
    "SubtleCrypto.unwrapKey:extractable",
    "SubtleCrypto.unwrapKey:key_usages_mask",
    "SubtleCrypto.unwrapKey:wrapped_key_ref",
    "SubtleCrypto.unwrapKey:wrapped_key_hex",
    "SubtleCrypto.unwrapKey:key_ref",
    "Crypto.getRandomValues:random_source",
    "Crypto.getRandomValues:typed_array_type",
    "Crypto.getRandomValues:byte_length",
    "Crypto.getRandomValues:array_buffer_id",
    "Crypto.getRandomValues:typed_array_id",
    "Crypto.getRandomValues:byte_offset",
    "Crypto.getRandomValues:result_ref",
    "Crypto.getRandomValues:result_hex",
    "Crypto.randomUUID:random_source",
    "Crypto.randomUUID:result",
    "Crypto.randomUUID:result_ref",
    "Crypto.randomUUID:result_length",
    "Math.random:result",
    "Math.random:result_ref",
    "Math.random:random_source",
    "Storage.getItem:result",
    "Storage.getItem:result_length",
    "Storage.getItem:result_ref",
    "Storage.key:result",
    "Storage.key:result_length",
    "Storage.key:result_ref",
    "Document.cookie.get:value",
    "Document.cookie.set:value",
    "Document.urlForBinding.get:result",
    "Document.referrer.get:result",
    "Node.baseURI.get:result",
    "CookieStore.get:name",
    "CookieStore.get:name_length",
    "CookieStore.get:name_ref",
    "CookieStore.getAll:name",
    "CookieStore.getAll:name_length",
    "CookieStore.getAll:name_ref",
    "CookieStore.set:name",
    "CookieStore.set:value",
    "CookieStore.delete:name",
    "AsyncFunction.enter:async_function_ref",
    "AsyncFunction.enter:closure_ref",
    "AsyncFunction.enter:receiver_ref",
    "AsyncFunction.enter:promise_ref",
    "AsyncFunction.enter:async_state",
    "AsyncFunction.await:async_function_ref",
    "AsyncFunction.await:await_value_ref",
    "AsyncFunction.await:outer_promise_ref",
    "AsyncFunction.await:await_mode",
    "AsyncFunction.await:async_state",
    "AsyncFunction.resume:async_function_ref",
    "AsyncFunction.resume:sent_value_ref",
    "AsyncFunction.resume:outer_promise_ref",
    "AsyncFunction.resume:resume_mode",
    "AsyncFunction.resume:async_state",
    "AsyncFunction.resolve:async_function_ref",
    "AsyncFunction.resolve:value_ref",
    "AsyncFunction.resolve:promise_ref",
    "AsyncFunction.resolve:settlement_state",
    "AsyncFunction.resolve:async_state",
    "AsyncFunction.reject:async_function_ref",
    "AsyncFunction.reject:reason_ref",
    "AsyncFunction.reject:promise_ref",
    "AsyncFunction.reject:settlement_state",
    "AsyncFunction.reject:async_state",
    "Array.prototype.at:result_ref",
    "Array.prototype.indexOf:search_ref",
    "Array.prototype.indexOf:from_index_ref",
    "Array.prototype.indexOf:result_ref",
    "Array.prototype.includes:search_ref",
    "Array.prototype.includes:from_index_ref",
    "Array.prototype.includes:result_ref",
    "Array.prototype.lastIndexOf:search_ref",
    "Array.prototype.lastIndexOf:from_index_ref",
    "Array.prototype.lastIndexOf:result_ref",
    "Array.prototype.find:callback_ref",
    "Array.prototype.find:this_arg_ref",
    "Array.prototype.find:result_ref",
    "Array.prototype.findIndex:callback_ref",
    "Array.prototype.findIndex:this_arg_ref",
    "Array.prototype.findIndex:result_ref",
    "Array.prototype.findLast:callback_ref",
    "Array.prototype.findLast:this_arg_ref",
    "Array.prototype.findLast:result_ref",
    "Array.prototype.findLastIndex:callback_ref",
    "Array.prototype.findLastIndex:this_arg_ref",
    "Array.prototype.findLastIndex:result_ref",
    "Array.prototype.reduce:callback_ref",
    "Array.prototype.reduce:initial_value_ref",
    "Array.prototype.reduce:result_ref",
    "Array.prototype.reduceRight:callback_ref",
    "Array.prototype.reduceRight:initial_value_ref",
    "Array.prototype.reduceRight:result_ref",
    "Array.prototype.map:callback_ref",
    "Array.prototype.map:this_arg_ref",
    "Array.prototype.map:result_ref",
    "Array.prototype.map:result_element_refs",
    "Array.prototype.filter:callback_ref",
    "Array.prototype.filter:this_arg_ref",
    "Array.prototype.filter:result_ref",
    "Array.prototype.filter:result_element_refs",
    "Array.prototype.flat:depth_ref",
    "Array.prototype.flat:result_ref",
    "Array.prototype.flat:result_element_refs",
    "Array.prototype.flatMap:callback_ref",
    "Array.prototype.flatMap:this_arg_ref",
    "Array.prototype.flatMap:result_ref",
    "Array.prototype.flatMap:result_element_refs",
    "Array.prototype.every:callback_ref",
    "Array.prototype.every:this_arg_ref",
    "Array.prototype.every:result_ref",
    "Array.prototype.some:callback_ref",
    "Array.prototype.some:this_arg_ref",
    "Array.prototype.some:result_ref",
    "Array.prototype.forEach:callback_ref",
    "Array.prototype.forEach:this_arg_ref",
    "Array.prototype.forEach:result_ref",
    "Reflect.construct:target_ref",
    "Reflect.construct:arguments_list_ref",
    "Reflect.construct:new_target_ref",
    "Reflect.construct:arg_count",
    "Reflect.construct:result_ref",
    "Object.assign:source_index",
    "Object.assign:source_count",
    "Object.assign:source_ref",
    "Object.assign:result_ref",
    "Object.hasOwn:object_ref",
    "Object.hasOwn:key_ref",
    "Object.hasOwn:result_ref",
    "Object.prototype.hasOwnProperty:object_ref",
    "Object.prototype.hasOwnProperty:key_ref",
    "Object.prototype.hasOwnProperty:result_ref",
    "Object.prototype.propertyIsEnumerable:object_ref",
    "Object.prototype.propertyIsEnumerable:key_ref",
    "Object.prototype.propertyIsEnumerable:result_ref",
    "Object.prototype.toString:receiver_ref",
    "Object.prototype.toString:result_ref",
    "Array.isArray:input_ref",
    "Array.isArray:result_ref",
    "Object.is:left_ref",
    "Object.is:right_ref",
    "Object.is:result_ref",
    "Object.create:prototype_ref",
    "Object.create:descriptors_ref",
    "Object.create:descriptors_kind",
    "Object.create:result_ref",
    "Object.getPrototypeOf:object_ref",
    "Object.getPrototypeOf:result_ref",
    "Object.setPrototypeOf:object_ref",
    "Object.setPrototypeOf:prototype_ref",
    "Object.setPrototypeOf:result_ref",
    "Object.getOwnPropertyDescriptor:object_ref",
    "Object.getOwnPropertyDescriptor:key_ref",
    "Object.getOwnPropertyDescriptor:result_ref",
    "Object.getOwnPropertyDescriptors:object_ref",
    "Object.getOwnPropertyDescriptors:descriptor_key_refs",
    "Object.getOwnPropertyDescriptors:result_ref",
    "Object.defineProperty:target_ref",
    "Object.defineProperty:key_ref",
    "Object.defineProperty:descriptor_ref",
    "Object.defineProperty:descriptor_kind",
    "Object.defineProperty:descriptor_value_ref",
    "Object.defineProperty:result_ref",
    "Object.defineProperties:target_ref",
    "Object.defineProperties:properties_ref",
    "Object.defineProperties:descriptor_key_refs",
    "Object.defineProperties:descriptor_kinds",
    "Object.defineProperties:descriptor_value_refs",
    "Object.defineProperties:result_ref",
    "Reflect.defineProperty:target_ref",
    "Reflect.defineProperty:key_ref",
    "Reflect.defineProperty:descriptor_ref",
    "Reflect.defineProperty:descriptor_kind",
    "Reflect.defineProperty:descriptor_value_ref",
    "Reflect.defineProperty:result_ref",
    "Object.preventExtensions:object_ref",
    "Object.preventExtensions:result_ref",
    "Object.freeze:object_ref",
    "Object.freeze:result_ref",
    "Object.seal:object_ref",
    "Object.seal:result_ref",
    "Object.isExtensible:object_ref",
    "Object.isExtensible:result_ref",
    "Object.isFrozen:object_ref",
    "Object.isFrozen:result_ref",
    "Object.isSealed:object_ref",
    "Object.isSealed:result_ref",
    "Reflect.preventExtensions:object_ref",
    "Reflect.preventExtensions:result_ref",
    "Reflect.isExtensible:object_ref",
    "Reflect.isExtensible:result_ref",
    "Reflect.get:object_ref",
    "Reflect.get:key_ref",
    "Reflect.get:result_ref",
    "Reflect.set:target_ref",
    "Reflect.set:key_ref",
    "Reflect.set:value_ref",
    "Reflect.set:receiver_ref",
    "Reflect.set:result_ref",
    "Reflect.has:object_ref",
    "Reflect.has:key_ref",
    "Reflect.has:result_ref",
    "Reflect.deleteProperty:object_ref",
    "Reflect.deleteProperty:key_ref",
    "Reflect.deleteProperty:result_ref",
    "Reflect.getPrototypeOf:object_ref",
    "Reflect.getPrototypeOf:result_ref",
    "Reflect.setPrototypeOf:object_ref",
    "Reflect.setPrototypeOf:prototype_ref",
    "Reflect.setPrototypeOf:result_ref",
    "Object.values:result_ref",
    "Object.values:result_element_refs",
    "Object.entries:result_ref",
    "Object.entries:result_element_refs",
    "Object.entries:result_entries",
    "Map.prototype.get:collection_ref",
    "Map.prototype.get:key_ref",
    "Map.prototype.get:result_ref",
    "Map.prototype.has:collection_ref",
    "Map.prototype.has:key_ref",
    "Map.prototype.has:result_ref",
    "Map.prototype.set:collection_ref",
    "Map.prototype.set:key_ref",
    "Map.prototype.set:value_ref",
    "Map.prototype.set:result_ref",
    "Map.prototype.delete:collection_ref",
    "Map.prototype.delete:key_ref",
    "Map.prototype.delete:result_ref",
    "Map.prototype.clear:collection_ref",
    "Map.prototype.clear:size_before",
    "Map.prototype.clear:result_ref",
    "Map.prototype.getOrInsert:collection_ref",
    "Map.prototype.getOrInsert:key_ref",
    "Map.prototype.getOrInsert:value_ref",
    "Map.prototype.getOrInsert:result_ref",
    "Map.prototype.getOrInsert:inserted",
    "Map.prototype.getOrInsertComputed:collection_ref",
    "Map.prototype.getOrInsertComputed:key_ref",
    "Map.prototype.getOrInsertComputed:callback_ref",
    "Map.prototype.getOrInsertComputed:result_ref",
    "Map.prototype.getOrInsertComputed:inserted",
    "Map.prototype.forEach:collection_ref",
    "Map.prototype.forEach:callback_ref",
    "Map.prototype.forEach:this_arg_ref",
    "Map.prototype.forEach:key_ref",
    "Map.prototype.forEach:value_ref",
    "Map.prototype.forEach:result_ref",
    "Map.prototype.entries:collection_ref",
    "Map.prototype.entries:iterator_ref",
    "Map.prototype.entries:result_ref",
    "Map.prototype.entries:iteration_kind",
    "Map.prototype.keys:collection_ref",
    "Map.prototype.keys:iterator_ref",
    "Map.prototype.keys:result_ref",
    "Map.prototype.keys:iteration_kind",
    "Map.prototype.values:collection_ref",
    "Map.prototype.values:iterator_ref",
    "Map.prototype.values:result_ref",
    "Map.prototype.values:iteration_kind",
    "MapIterator.prototype.next:iterator_ref",
    "MapIterator.prototype.next:key_ref",
    "MapIterator.prototype.next:value_ref",
    "MapIterator.prototype.next:result_ref",
    "MapIterator.prototype.next:done",
    "Set.prototype.add:collection_ref",
    "Set.prototype.add:key_ref",
    "Set.prototype.add:value_ref",
    "Set.prototype.add:result_ref",
    "Set.prototype.has:collection_ref",
    "Set.prototype.has:key_ref",
    "Set.prototype.has:result_ref",
    "Set.prototype.delete:collection_ref",
    "Set.prototype.delete:key_ref",
    "Set.prototype.delete:result_ref",
    "Set.prototype.clear:collection_ref",
    "Set.prototype.clear:size_before",
    "Set.prototype.clear:result_ref",
    "Set.prototype.forEach:collection_ref",
    "Set.prototype.forEach:callback_ref",
    "Set.prototype.forEach:this_arg_ref",
    "Set.prototype.forEach:key_ref",
    "Set.prototype.forEach:value_ref",
    "Set.prototype.forEach:result_ref",
    "Set.prototype.entries:collection_ref",
    "Set.prototype.entries:iterator_ref",
    "Set.prototype.entries:result_ref",
    "Set.prototype.entries:iteration_kind",
    "Set.prototype.values:collection_ref",
    "Set.prototype.values:iterator_ref",
    "Set.prototype.values:result_ref",
    "Set.prototype.values:iteration_kind",
    "SetIterator.prototype.next:iterator_ref",
    "SetIterator.prototype.next:key_ref",
    "SetIterator.prototype.next:value_ref",
    "SetIterator.prototype.next:result_ref",
    "SetIterator.prototype.next:done",
    "WeakMap.prototype.get:collection_ref",
    "WeakMap.prototype.get:key_ref",
    "WeakMap.prototype.get:result_ref",
    "WeakMap.prototype.has:collection_ref",
    "WeakMap.prototype.has:key_ref",
    "WeakMap.prototype.has:result_ref",
    "WeakMap.prototype.set:collection_ref",
    "WeakMap.prototype.set:key_ref",
    "WeakMap.prototype.set:value_ref",
    "WeakMap.prototype.set:result_ref",
    "WeakMap.prototype.delete:collection_ref",
    "WeakMap.prototype.delete:key_ref",
    "WeakMap.prototype.delete:result_ref",
    "WeakMap.prototype.getOrInsert:collection_ref",
    "WeakMap.prototype.getOrInsert:key_ref",
    "WeakMap.prototype.getOrInsert:value_ref",
    "WeakMap.prototype.getOrInsert:result_ref",
    "WeakMap.prototype.getOrInsert:inserted",
    "WeakMap.prototype.getOrInsertComputed:collection_ref",
    "WeakMap.prototype.getOrInsertComputed:key_ref",
    "WeakMap.prototype.getOrInsertComputed:callback_ref",
    "WeakMap.prototype.getOrInsertComputed:result_ref",
    "WeakMap.prototype.getOrInsertComputed:inserted",
    "WeakSet.prototype.add:collection_ref",
    "WeakSet.prototype.add:key_ref",
    "WeakSet.prototype.add:value_ref",
    "WeakSet.prototype.add:result_ref",
    "WeakSet.prototype.has:collection_ref",
    "WeakSet.prototype.has:key_ref",
    "WeakSet.prototype.has:result_ref",
    "WeakSet.prototype.delete:collection_ref",
    "WeakSet.prototype.delete:key_ref",
    "WeakSet.prototype.delete:result_ref",
    "TypedArray.indexOf:search_ref",
    "TypedArray.indexOf:from_index_ref",
    "TypedArray.indexOf:result_ref",
    "TypedArray.includes:search_ref",
    "TypedArray.includes:from_index_ref",
    "TypedArray.includes:result_ref",
    "TypedArray.lastIndexOf:search_ref",
    "TypedArray.lastIndexOf:from_index_ref",
    "TypedArray.lastIndexOf:result_ref",
    "TypedArray.find:callback_ref",
    "TypedArray.find:this_arg_ref",
    "TypedArray.find:result_ref",
    "TypedArray.findIndex:callback_ref",
    "TypedArray.findIndex:this_arg_ref",
    "TypedArray.findIndex:result_ref",
    "TypedArray.findLast:callback_ref",
    "TypedArray.findLast:this_arg_ref",
    "TypedArray.findLast:result_ref",
    "TypedArray.findLastIndex:callback_ref",
    "TypedArray.findLastIndex:this_arg_ref",
    "TypedArray.findLastIndex:result_ref",
    "TypedArray.reduce:callback_ref",
    "TypedArray.reduce:initial_value_ref",
    "TypedArray.reduce:result_ref",
    "TypedArray.reduceRight:callback_ref",
    "TypedArray.reduceRight:initial_value_ref",
    "TypedArray.reduceRight:result_ref",
    "TypedArray.filter:callback_ref",
    "TypedArray.filter:this_arg_ref",
    "TypedArray.filter:result_ref",
    "TypedArray.filter:result_element_refs",
    "TypedArray.every:callback_ref",
    "TypedArray.every:this_arg_ref",
    "TypedArray.every:result_ref",
    "TypedArray.some:callback_ref",
    "TypedArray.some:this_arg_ref",
    "TypedArray.some:result_ref",
    "TypedArray.forEach:callback_ref",
    "TypedArray.forEach:this_arg_ref",
    "TypedArray.forEach:result_ref",
    "TypedArray.entries:sequence_ref",
    "TypedArray.entries:iterator_ref",
    "TypedArray.entries:result_ref",
    "TypedArray.entries:iteration_kind",
    "TypedArray.keys:sequence_ref",
    "TypedArray.keys:iterator_ref",
    "TypedArray.keys:result_ref",
    "TypedArray.keys:iteration_kind",
    "TypedArray.values:sequence_ref",
    "TypedArray.values:iterator_ref",
    "TypedArray.values:result_ref",
    "TypedArray.values:iteration_kind",
    "Array.prototype.entries:sequence_ref",
    "Array.prototype.entries:iterator_ref",
    "Array.prototype.entries:result_ref",
    "Array.prototype.entries:iteration_kind",
    "Array.prototype.keys:sequence_ref",
    "Array.prototype.keys:iterator_ref",
    "Array.prototype.keys:result_ref",
    "Array.prototype.keys:iteration_kind",
    "Array.prototype.values:sequence_ref",
    "Array.prototype.values:iterator_ref",
    "Array.prototype.values:result_ref",
    "Array.prototype.values:iteration_kind",
    "ArrayIterator.prototype.next:iterator_ref",
    "ArrayIterator.prototype.next:key_ref",
    "ArrayIterator.prototype.next:value_ref",
    "ArrayIterator.prototype.next:result_ref",
    "ArrayIterator.prototype.next:done",
    "String.prototype.@@iterator:sequence_ref",
    "String.prototype.@@iterator:iterator_ref",
    "String.prototype.@@iterator:result_ref",
    "String.prototype.@@iterator:iteration_kind",
    "StringIterator.prototype.next:iterator_ref",
    "StringIterator.prototype.next:key_ref",
    "StringIterator.prototype.next:value_ref",
    "StringIterator.prototype.next:result_ref",
    "StringIterator.prototype.next:done",
    "Generator.prototype.next:generator_ref",
    "Generator.prototype.next:input_ref",
    "Generator.prototype.next:result_ref",
    "Generator.prototype.next:resume_mode",
    "Generator.prototype.next:generator_state",
    "Generator.prototype.return:generator_ref",
    "Generator.prototype.return:input_ref",
    "Generator.prototype.return:result_ref",
    "Generator.prototype.return:resume_mode",
    "Generator.prototype.return:generator_state",
    "Generator.prototype.throw:generator_ref",
    "Generator.prototype.throw:input_ref",
    "Generator.prototype.throw:result_ref",
    "Generator.prototype.throw:resume_mode",
    "Generator.prototype.throw:generator_state",
    "AsyncGenerator.prototype.next:generator_ref",
    "AsyncGenerator.prototype.next:input_ref",
    "AsyncGenerator.prototype.next:request_promise_ref",
    "AsyncGenerator.prototype.next:resume_mode",
    "AsyncGenerator.prototype.next:generator_state",
    "AsyncGenerator.prototype.return:generator_ref",
    "AsyncGenerator.prototype.return:input_ref",
    "AsyncGenerator.prototype.return:request_promise_ref",
    "AsyncGenerator.prototype.return:resume_mode",
    "AsyncGenerator.prototype.return:generator_state",
    "AsyncGenerator.prototype.throw:generator_ref",
    "AsyncGenerator.prototype.throw:input_ref",
    "AsyncGenerator.prototype.throw:request_promise_ref",
    "AsyncGenerator.prototype.throw:resume_mode",
    "AsyncGenerator.prototype.throw:generator_state",
    "Headers.append:headers_id",
    "Headers.append:name",
    "Headers.append:name_length",
    "Headers.append:name_ref",
    "Headers.append:value",
    "Headers.append:value_length",
    "Headers.append:value_ref",
    "Headers.append:normalized_value",
    "Headers.append:normalized_value_length",
    "Headers.append:normalized_value_ref",
    "Headers.set:headers_id",
    "Headers.set:name",
    "Headers.set:name_length",
    "Headers.set:name_ref",
    "Headers.set:value",
    "Headers.set:value_length",
    "Headers.set:value_ref",
    "Headers.set:normalized_value",
    "Headers.set:normalized_value_length",
    "Headers.set:normalized_value_ref",
    "Headers.constructor:headers_id",
    "Headers.constructor:has_init",
    "Headers.constructor:init_type",
    "Headers.constructor:entry_count",
    "Headers.constructor:headers",
    "Headers.iterator.next:headers_id",
    "Headers.iterator.next:iteration_index",
    "Headers.iterator.next:name",
    "Headers.iterator.next:name_length",
    "Headers.iterator.next:name_ref",
    "Headers.iterator.next:value",
    "Headers.iterator.next:value_length",
    "Headers.iterator.next:value_ref",
    "Headers.has:headers_id",
    "Headers.has:name",
    "Headers.has:name_length",
    "Headers.has:name_ref",
    "Headers.has:result",
    "Headers.delete:headers_id",
    "Headers.delete:name",
    "Headers.delete:name_length",
    "Headers.delete:name_ref",
    "Headers.delete:removed",
    "FormData.constructor:form_data_id",
    "FormData.constructor:cloned_from_form_data_id",
    "FormData.constructor:entry_count",
    "FormData.constructor:entries",
    "URLSearchParams.constructor:search_params_id",
    "URLSearchParams.constructor:url_object_id",
    "URLSearchParams.constructor:init_type",
    "URLSearchParams.constructor:has_init",
    "URLSearchParams.constructor:entry_count",
    "URLSearchParams.constructor:param_names",
    "URLSearchParams.constructor:param_name_lengths",
    "URLSearchParams.constructor:param_name_refs",
    "URLSearchParams.constructor:param_values",
    "URLSearchParams.constructor:param_value_lengths",
    "URLSearchParams.constructor:param_value_refs",
    "URLSearchParams.constructor:serialized",
    "URLSearchParams.constructor:serialized_length",
    "URLSearchParams.constructor:serialized_ref",
    "URLSearchParams.iterator.next:search_params_id",
    "URLSearchParams.iterator.next:url_object_id",
    "URLSearchParams.iterator.next:iteration_index",
    "URLSearchParams.iterator.next:name",
    "URLSearchParams.iterator.next:name_length",
    "URLSearchParams.iterator.next:name_ref",
    "URLSearchParams.iterator.next:value",
    "URLSearchParams.iterator.next:value_length",
    "URLSearchParams.iterator.next:value_ref",
    "URLSearchParams.append:search_params_id",
    "URLSearchParams.append:url_object_id",
    "URLSearchParams.append:name",
    "URLSearchParams.append:name_length",
    "URLSearchParams.append:name_ref",
    "URLSearchParams.append:value",
    "URLSearchParams.append:value_length",
    "URLSearchParams.append:value_ref",
    "URLSearchParams.delete:search_params_id",
    "URLSearchParams.delete:url_object_id",
    "URLSearchParams.delete:name",
    "URLSearchParams.delete:name_length",
    "URLSearchParams.delete:name_ref",
    "URLSearchParams.delete:value",
    "URLSearchParams.delete:value_length",
    "URLSearchParams.delete:value_ref",
    "URLSearchParams.get:search_params_id",
    "URLSearchParams.get:url_object_id",
    "URLSearchParams.get:name",
    "URLSearchParams.get:name_length",
    "URLSearchParams.get:name_ref",
    "URLSearchParams.get:result",
    "URLSearchParams.get:result_length",
    "URLSearchParams.get:result_ref",
    "URLSearchParams.getAll:search_params_id",
    "URLSearchParams.getAll:url_object_id",
    "URLSearchParams.getAll:name",
    "URLSearchParams.getAll:name_length",
    "URLSearchParams.getAll:name_ref",
    "URLSearchParams.getAll:result_count",
    "URLSearchParams.getAll:values",
    "URLSearchParams.getAll:result_value_lengths",
    "URLSearchParams.getAll:result_value_refs",
    "URLSearchParams.has:search_params_id",
    "URLSearchParams.has:url_object_id",
    "URLSearchParams.has:name",
    "URLSearchParams.has:name_length",
    "URLSearchParams.has:name_ref",
    "URLSearchParams.has:result",
    "FormData.append:form_data_id",
    "FormData.append:name",
    "FormData.append:name_length",
    "FormData.append:name_ref",
    "FormData.append:value_kind",
    "FormData.set:form_data_id",
    "FormData.set:name",
    "FormData.set:name_length",
    "FormData.set:name_ref",
    "FormData.set:value_kind",
    "FormData.delete:form_data_id",
    "FormData.delete:name",
    "FormData.delete:name_length",
    "FormData.delete:name_ref",
    "FormData.delete:removed_count",
    "FormData.get:form_data_id",
    "FormData.get:name",
    "FormData.get:name_length",
    "FormData.get:name_ref",
    "FormData.get:found",
    "FormData.getAll:form_data_id",
    "FormData.getAll:name",
    "FormData.getAll:name_length",
    "FormData.getAll:name_ref",
    "FormData.getAll:result_count",
    "FormData.has:form_data_id",
    "FormData.has:name",
    "FormData.has:name_length",
    "FormData.has:name_ref",
    "FormData.has:result",
    "FormData.iterator.next:form_data_id",
    "FormData.iterator.next:iteration_index",
    "FormData.iterator.next:name",
    "FormData.iterator.next:name_length",
    "FormData.iterator.next:name_ref",
    "FormData.iterator.next:value_kind",
    "Request.constructor:method",
    "Request.constructor:url",
    "Request.constructor:url_ref",
    "Request.constructor:headers_id",
    "Request.constructor:has_body",
    "Request.constructor:body_byte_length",
    "Request.constructor:body",
    "Request.constructor:body_ref",
    "Request.constructor:network_correlation_key",
    "fetch:method",
    "fetch:url",
    "fetch:url_ref",
    "fetch:headers_id",
    "fetch:has_body",
    "fetch:body_byte_length",
    "fetch:network_correlation_key",
    "XMLHttpRequest.open:method",
    "XMLHttpRequest.open:url",
    "XMLHttpRequest.open:url_ref",
    "XMLHttpRequest.open:network_correlation_key",
    "XMLHttpRequest.setRequestHeader:xhr_id",
    "XMLHttpRequest.setRequestHeader:method",
    "XMLHttpRequest.setRequestHeader:url",
    "XMLHttpRequest.setRequestHeader:url_ref",
    "XMLHttpRequest.setRequestHeader:network_correlation_key",
    "XMLHttpRequest.setRequestHeader:name",
    "XMLHttpRequest.setRequestHeader:name_length",
    "XMLHttpRequest.setRequestHeader:name_ref",
    "XMLHttpRequest.setRequestHeader:value",
    "XMLHttpRequest.setRequestHeader:value_length",
    "XMLHttpRequest.setRequestHeader:value_ref",
    "XMLHttpRequest.setRequestHeader:normalized_value",
    "XMLHttpRequest.setRequestHeader:normalized_value_length",
    "XMLHttpRequest.setRequestHeader:normalized_value_ref",
    "XMLHttpRequest.send:method",
    "XMLHttpRequest.send:url",
    "XMLHttpRequest.send:url_ref",
    "XMLHttpRequest.send:network_correlation_key",
    "XMLHttpRequest.send:body_type",
    "XMLHttpRequest.send:body_size",
    "XMLHttpRequest.send:body",
    "XMLHttpRequest.send:body_ref",
    "XMLHttpRequest.responseText:xhr_id",
    "XMLHttpRequest.responseText:url",
    "XMLHttpRequest.responseText:url_ref",
    "XMLHttpRequest.responseText:network_correlation_key",
    "XMLHttpRequest.responseText:status",
    "XMLHttpRequest.responseText:value",
    "XMLHttpRequest.responseText:value_length",
    "XMLHttpRequest.responseText:value_ref",
]
SIGNATURE_PARAM_MATERIALIZATION_APIS = {
    "String.fromCharCode",
    "String.fromCodePoint",
    "String.prototype.codePointAt",
    "String.prototype.charAt",
    "String.prototype.concat",
    "String.prototype.slice",
    "String.prototype.substring",
    "String.prototype.substr",
    "String.prototype.repeat",
    "String.prototype.replace",
    "String.prototype.toLowerCase",
    "String.prototype.toUpperCase",
    "StringAdd",
    "StringAdd.constant_lhs",
    "StringAdd.constant_rhs",
    "Array.prototype.join",
    "TypedArray.join",
    "Number.prototype.toString",
    "BigInt.prototype.toString",
    "encodeURI",
    "encodeURIComponent",
    "decodeURI",
    "decodeURIComponent",
    "URLSearchParams.constructor",
    "URLSearchParams.append",
    "URLSearchParams.delete",
    "URLSearchParams.get",
    "URLSearchParams.getAll",
    "URLSearchParams.has",
    "URLSearchParams.set",
    "URLSearchParams.iterator.next",
    "URLSearchParams.toString",
    "URL.href.set",
    "URL.search.set",
    "Location.href.set",
    "Location.search.set",
    "Location.assign",
    "Location.replace",
    "Headers.constructor",
    "Headers.append",
    "Headers.get",
    "Headers.iterator.next",
    "Headers.set",
    "XMLHttpRequest.setRequestHeader",
    "CookieStore.get",
    "CookieStore.getAll",
    "CookieStore.set",
    "FormData.constructor",
    "FormData.append",
    "FormData.delete",
    "FormData.get",
    "FormData.getAll",
    "FormData.has",
    "FormData.set",
    "FormData.iterator.next",
}
SIGNATURE_PARAM_CARRIER_APIS = {
    "Request.constructor",
    "Request.url.get",
    "fetch",
    "XMLHttpRequest.open",
    "XMLHttpRequest.send",
    "BrowserNetwork.request",
}
SCHEMA_V1_REQUIRED_FIELDS = [
    "schema_version",
    "event_id",
    "session_id",
    "seq",
    "t",
    "wall_time_us",
    "mono_time_us",
    "category",
    "phase",
    "api",
    "args",
    "stack",
    "pid",
    "tid",
    "frame_url",
    "origin",
    "result",
    "error",
    "truncated",
]
SCHEMA_V1_PHASES = {
    "call",
    "return",
    "exception",
    "get",
    "set",
    "lifecycle",
    "complete",
    "iterate",
}
SCHEMA_V2_REQUIRED_FIELDS = SCHEMA_V1_REQUIRED_FIELDS + [
    "call_id",
    "parent_id",
    "depth",
    "causality_kind",
    "duration_us",
]
SCHEMA_V2_CAUSALITY_KINDS = {"paired", "singleton", "external"}
REDACTED_VALUE_MARKERS = {
    "redacted",
    "<redacted>",
    "[redacted]",
    "(redacted)",
    "***redacted***",
}
VMP_METADATA_ARG_FIELDS = {
    "algorithm",
    "body_type",
    "count",
    "end",
    "has_body",
    "index",
    "little_endian",
    "method",
    "network_correlation_key",
    "position",
    "radix",
    "shape",
    "start",
    "status",
    "type",
}


class TraceValidationError(Exception):
    pass


def load_events(path: Path) -> list[dict]:
    events: list[dict] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                event = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise TraceValidationError(f"Malformed JSON on line {line_number}: {exc}") from exc
            if not isinstance(event, dict):
                raise TraceValidationError(f"Expected object on line {line_number}")
            event.setdefault("_file_index", len(events))
            events.append(event)
    if not events:
        raise TraceValidationError(f"No events found in {path}")
    return events


def validate_schema_v1_event(event: dict, index: int) -> None:
    if event.get("schema_version") != 1:
        raise TraceValidationError(f"Event {index} has schema_version={event.get('schema_version')!r}, expected 1")

    missing = [field for field in SCHEMA_V1_REQUIRED_FIELDS if field not in event]
    if missing:
        raise TraceValidationError(f"Event {index} missing schema v1 fields: {', '.join(missing)}")

    if event["phase"] not in SCHEMA_V1_PHASES:
        raise TraceValidationError(f"Event {index} has invalid phase: {event['phase']!r}")
    if not isinstance(event["truncated"], bool):
        raise TraceValidationError(f"Event {index} has non-boolean truncated field")

    for field in ("global_seq", "session_seq"):
        if field in event and not (
            isinstance(event[field], int) and not isinstance(event[field], bool)
        ):
            raise TraceValidationError(f"Event {index} has non-integer {field} field")

    if event["truncated"]:
        truncation = event.get("truncation")
        if not isinstance(truncation, dict):
            raise TraceValidationError(f"Event {index} truncated=true requires truncation metadata")
        for field in ("original_size", "preview", "hash"):
            if field not in truncation:
                raise TraceValidationError(f"Event {index} truncation metadata missing {field}")


def validate_schema_v2_event(event: dict, index: int) -> None:
    """Validate the per-record portion of the schema v2 causal contract."""
    if event.get("schema_version") != 2:
        raise TraceValidationError(
            f"Event {index} has schema_version={event.get('schema_version')!r}, expected 2"
        )
    missing = [field for field in SCHEMA_V2_REQUIRED_FIELDS if field not in event]
    if missing:
        raise TraceValidationError(f"Event {index} missing schema v2 fields: {', '.join(missing)}")
    if event["phase"] not in SCHEMA_V1_PHASES:
        raise TraceValidationError(f"Event {index} has invalid phase: {event['phase']!r}")
    if not isinstance(event["truncated"], bool):
        raise TraceValidationError(f"Event {index} has non-boolean truncated field")
    if event["causality_kind"] not in SCHEMA_V2_CAUSALITY_KINDS:
        raise TraceValidationError(
            f"Event {index} has invalid causality_kind: {event['causality_kind']!r}"
        )
    if not isinstance(event["depth"], int) or isinstance(event["depth"], bool) or event["depth"] < 0:
        raise TraceValidationError(f"Event {index} has invalid non-negative depth")
    if event["parent_id"] is not None and not isinstance(event["parent_id"], str):
        raise TraceValidationError(f"Event {index} has non-string parent_id")
    if event["duration_us"] is not None and (
        not isinstance(event["duration_us"], int)
        or isinstance(event["duration_us"], bool)
        or event["duration_us"] < 0
    ):
        raise TraceValidationError(f"Event {index} has invalid duration_us")
    if event["causality_kind"] == "external":
        if any(event[field] is not None for field in ("call_id", "parent_id", "duration_us")):
            raise TraceValidationError(f"Event {index} external record must have empty causal IDs/duration")
        if event["depth"] != 0:
            raise TraceValidationError(f"Event {index} external record must have depth 0")
    else:
        if not isinstance(event["call_id"], str) or not event["call_id"]:
            raise TraceValidationError(f"Event {index} causal record needs non-empty call_id")
        session_prefix, separator, activation_seq = event["call_id"].rpartition(":")
        if (
            not separator
            or session_prefix != event["session_id"]
            or not activation_seq.isdecimal()
        ):
            raise TraceValidationError(
                f"Event {index} call_id must be session_id:activation_seq"
            )
        if event["causality_kind"] == "singleton" and event["duration_us"] is not None:
            raise TraceValidationError(f"Event {index} singleton record must have duration_us=null")


def validate_causality(events: list[dict]) -> None:
    """Validate the cross-event tree and paired activation invariants for v2."""
    nodes: dict[str, tuple[int, int]] = {}
    pairs: dict[str, dict] = {}
    for index, event in enumerate(events, start=1):
        kind = event["causality_kind"]
        if kind == "external":
            continue
        call_id = event["call_id"]
        parent_id = event["parent_id"]
        depth = event["depth"]
        phase = event["phase"]
        is_paired_call = kind == "paired" and phase == "call"
        is_paired_terminal = kind == "paired" and phase in {"return", "exception"}
        if kind == "paired" and not (is_paired_call or is_paired_terminal):
            raise TraceValidationError(f"Event {index} paired record must be call, return, or exception")
        if kind == "paired" and is_paired_call and event["duration_us"] is not None:
            raise TraceValidationError(f"Event {index} paired call must have duration_us=null")
        if kind == "paired" and is_paired_terminal and event["duration_us"] is None:
            raise TraceValidationError(f"Event {index} paired terminal needs duration_us")

        if is_paired_terminal:
            pair = pairs.get(call_id)
            if pair is None:
                raise TraceValidationError(f"Event {index} has orphan paired terminal {call_id}")
            if pair.get("terminal_index") is not None:
                raise TraceValidationError(f"Event {index} has duplicate paired terminal {call_id}")
            if (
                pair["api"] != event["api"]
                or pair["parent_id"] != parent_id
                or pair["depth"] != depth
            ):
                raise TraceValidationError(f"Event {index} paired terminal disagrees with its call")
            pair["terminal_index"] = index
            continue

        if call_id in nodes:
            raise TraceValidationError(f"Event {index} reuses causal call_id {call_id}")
        if parent_id is None:
            if depth != 0:
                raise TraceValidationError(f"Event {index} root causal node must have depth 0")
        else:
            parent_session, separator, _ = parent_id.rpartition(":")
            if not separator or parent_session != event["session_id"]:
                raise TraceValidationError(f"Event {index} crosses producer sessions")
            parent = nodes.get(parent_id)
            if parent is None:
                raise TraceValidationError(f"Event {index} has missing or forward parent {parent_id}")
            if depth != parent[1] + 1:
                raise TraceValidationError(f"Event {index} depth does not follow parent {parent_id}")
        nodes[call_id] = (index, depth)
        if is_paired_call:
            pairs[call_id] = {
                "api": event["api"],
                "parent_id": parent_id,
                "depth": depth,
                "terminal_index": None,
            }

    unclosed = [call_id for call_id, pair in pairs.items() if pair["terminal_index"] is None]
    if unclosed:
        raise TraceValidationError("Unclosed paired activations: " + ", ".join(unclosed[:20]))


def validate_global_sequence(events: list[dict]) -> None:
    has_global_seq = ["global_seq" in event for event in events]
    if not any(has_global_seq):
        return
    if not all(has_global_seq):
        missing = [str(index) for index, present in enumerate(has_global_seq, start=1) if not present]
        raise TraceValidationError(
            "Partial global_seq coverage; missing event indexes: " + ", ".join(missing[:20])
        )

    previous = 0
    for index, event in enumerate(events, start=1):
        value = event.get("global_seq")
        if not isinstance(value, int) or isinstance(value, bool):
            raise TraceValidationError(f"Event {index} has non-integer global_seq field")
        if value <= previous:
            raise TraceValidationError(
                f"Event {index} has non-monotonic global_seq: {value} <= {previous}"
            )
        previous = value


def validate_context_for_apis(events: list[dict], apis: Iterable[str]) -> None:
    """Require non-empty frame and origin attribution for selected APIs.

    Context availability is producer- and API-dependent, so this stays an
    explicit contract chosen by the caller instead of a blanket v1 rule.  It is
    useful for smoke captures of APIs that are documented to receive an
    ExecutionContext or request initiator.
    """
    for api in sorted(set(apis)):
        matching = [(index, event) for index, event in enumerate(events, start=1)
                    if event.get("api") == api]
        if not matching:
            raise TraceValidationError(f"Required context API was not observed: {api}")
        missing = [str(index) for index, event in matching
                   if not isinstance(event.get("frame_url"), str) or not event["frame_url"]
                   or not isinstance(event.get("origin"), str) or not event["origin"]]
        if missing:
            raise TraceValidationError(
                f"Missing non-empty frame_url/origin for {api} at event indexes: "
                + ", ".join(missing[:20])
            )


def parse_required_arg_field(spec: str) -> tuple[str, str]:
    api, separator, field = spec.partition(":")
    if not separator or not api or not field:
        raise TraceValidationError(
            f"Invalid required arg field {spec!r}; expected API:field"
        )
    return api, field


def is_preview_field(key: str) -> bool:
    return key == "preview" or key.endswith("_preview")


def is_redaction_field(key: str) -> bool:
    return key == "redacted" or key.endswith("_redacted")


def is_redacted_marker(value: str) -> bool:
    normalized = value.strip().lower()
    return normalized in REDACTED_VALUE_MARKERS or "redacted" in normalized


def child_path(path: str, key: str) -> str:
    return f"{path}.{key}" if path else key


def index_path(path: str, index: int) -> str:
    return f"{path}[{index}]" if path else f"[{index}]"


def iter_partial_value_evidence(value, path: str = ""):
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            item_path = child_path(path, key_text)
            if is_preview_field(key_text):
                yield "preview field", item_path
            if is_redaction_field(key_text) and item is True:
                yield "redacted marker", item_path
            yield from iter_partial_value_evidence(item, item_path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from iter_partial_value_evidence(item, index_path(path, index))
    elif isinstance(value, str) and is_redacted_marker(value):
        yield "redacted marker", path


def value_has_material_evidence(value) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            if is_preview_field(key_text) or is_redaction_field(key_text):
                continue
            if value_has_material_evidence(item):
                return True
        return False
    if isinstance(value, list):
        return any(value_has_material_evidence(item) for item in value)
    if isinstance(value, str):
        return bool(value.strip()) and not is_redacted_marker(value)
    return value is not None


def value_has_field(value, field: str) -> bool:
    if isinstance(value, dict):
        if field in value:
            return value_has_material_evidence(value[field])
        return any(value_has_field(item, field) for item in value.values())
    if isinstance(value, list):
        return any(value_has_field(item, field) for item in value)
    return False


def value_has_key(value, field: str) -> bool:
    if isinstance(value, dict):
        if field in value:
            return True
        return any(value_has_key(item, field) for item in value.values())
    if isinstance(value, list):
        return any(value_has_key(item, field) for item in value)
    return False


FORM_DATA_STRING_VALUE_FIELDS = ("value", "value_length", "value_ref")
FORM_DATA_STRING_RESULT_FIELDS = ("result_length", "result_ref")
FORM_DATA_GET_ALL_STRING_FIELDS = (
    "values",
    "result_value_lengths",
    "result_value_refs",
)
FORM_DATA_BLOB_FIELDS = (
    "filename",
    "filename_length",
    "filename_ref",
    "blob_type",
    "blob_type_length",
    "blob_type_ref",
    "blob_size",
    "blob_uuid",
    "blob_uuid_ref",
)
FORM_DATA_GET_ALL_BLOB_FIELDS = (
    "blob_filenames",
    "blob_filename_lengths",
    "blob_filename_refs",
    "blob_types",
    "blob_type_lengths",
    "blob_type_refs",
    "blob_sizes",
    "blob_uuids",
    "blob_uuid_refs",
)


def missing_form_data_branch_fields(events: list[dict]) -> list[str]:
    missing: list[str] = []
    for event in events:
        api = event.get("api")
        if api not in {
            "FormData.append",
            "FormData.set",
            "FormData.get",
            "FormData.getAll",
            "FormData.iterator.next",
        }:
            continue
        arg = first_arg(event)
        if not arg:
            continue

        if api in {"FormData.append", "FormData.set", "FormData.iterator.next"}:
            fields = (
                FORM_DATA_BLOB_FIELDS
                if arg.get("value_kind") == "blob"
                else FORM_DATA_STRING_VALUE_FIELDS
            )
        elif api == "FormData.get":
            if arg.get("found") is not True:
                continue
            fields = (
                FORM_DATA_BLOB_FIELDS
                if arg.get("value_kind") == "blob"
                else FORM_DATA_STRING_RESULT_FIELDS
            )
        else:
            fields = ()
            if arg.get("string_count", 0) or "values" in arg:
                fields += FORM_DATA_GET_ALL_STRING_FIELDS
            if arg.get("blob_count", 0):
                fields += FORM_DATA_GET_ALL_BLOB_FIELDS

        for field in fields:
            if not value_has_key(arg, field):
                missing.append(f"{api}:{field}")
    return missing


def is_ref_field(key: str) -> bool:
    return key == "ref" or key.endswith("_ref") or key.endswith("_refs")


SUMMARY_REF_PREFIXES = (
    "string:length:",
    "js-string:length",
    "bytes:length:",
    "byte:length:",
    "array:length:",
    "object:length:",
)
OPAQUE_REF_PREFIXES = (
    "string_ref:",
    "bytes_sha1:",
)


def is_summary_ref(value: str) -> bool:
    return value.startswith(SUMMARY_REF_PREFIXES)


def is_opaque_ref(value: str) -> bool:
    return value.startswith(OPAQUE_REF_PREFIXES)


def value_has_raw_material_evidence(value) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            if is_preview_field(key_text) or is_redaction_field(key_text):
                continue
            if value_has_raw_material_evidence(item):
                return True
        return False
    if isinstance(value, list):
        return any(value_has_raw_material_evidence(item) for item in value)
    if isinstance(value, str):
        return (
            not is_redacted_marker(value)
            and not is_summary_ref(value)
            and not is_opaque_ref(value)
        )
    return value is not None


def raw_material_candidate_fields(ref_field: str) -> tuple[str, ...]:
    if ref_field == "ref":
        return ("value", "result", "source", "body", "body_hex")
    if ref_field.endswith("_refs"):
        base = ref_field[:-5]
        return (
            base,
            f"{base}s",
            f"{base}_values",
            f"{base}_hex",
            f"{base}_hexes",
        )
    if ref_field.endswith("_ref"):
        base = ref_field[:-4]
        candidates = (
            base,
            f"{base}_value",
            f"{base}_text",
            f"{base}_string",
            f"{base}_hex",
            f"{base}_bytes",
        )
        if ref_field == "result_ref":
            return candidates + ("serialized",)
        return candidates
    return ()


def container_has_raw_material_for_ref(container: dict, ref_field: str) -> bool:
    return any(
        field in container and value_has_raw_material_evidence(container[field])
        for field in raw_material_candidate_fields(ref_field)
    )


def iter_summary_ref_values(value, path: str = "", *, in_ref_field: bool = False):
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            item_path = child_path(path, key_text)
            yield from iter_summary_ref_values(
                item,
                item_path,
                in_ref_field=in_ref_field or is_ref_field(key_text),
            )
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from iter_summary_ref_values(
                item,
                index_path(path, index),
                in_ref_field=in_ref_field,
            )
    elif in_ref_field and isinstance(value, str) and is_summary_ref(value):
        yield path


def iter_opaque_ref_leaf_paths(value, path: str):
    if isinstance(value, list):
        for index, item in enumerate(value):
            yield from iter_opaque_ref_leaf_paths(item, index_path(path, index))
    elif isinstance(value, str) and is_opaque_ref(value):
        yield path


def iter_opaque_refs_without_raw_material(value, path: str = ""):
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            item_path = child_path(path, key_text)
            if is_ref_field(key_text):
                if not container_has_raw_material_for_ref(value, key_text):
                    yield from iter_opaque_ref_leaf_paths(item, item_path)
                continue
            yield from iter_opaque_refs_without_raw_material(item, item_path)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from iter_opaque_refs_without_raw_material(item, index_path(path, index))


def iter_dict_values(value, *, include_preview: bool = True):
    if isinstance(value, dict):
        for key, item in value.items():
            if not include_preview and is_preview_field(str(key)):
                continue
            yield from iter_dict_values(item, include_preview=include_preview)
    elif isinstance(value, list):
        for item in value:
            yield from iter_dict_values(item, include_preview=include_preview)
    else:
        yield value


def iter_string_values(value, *, include_preview: bool = True) -> Iterable[str]:
    for item in iter_dict_values(value, include_preview=include_preview):
        if isinstance(item, str):
            yield item


def value_has_ref(value) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if is_ref_field(str(key)):
                if value_has_material_evidence(item):
                    return True
                continue
            if value_has_ref(item):
                return True
    if isinstance(value, list):
        return any(value_has_ref(item) for item in value)
    if isinstance(value, str):
        return value.startswith(("string_ref:", "string:", "bytes_sha", "register:"))
    return False


def value_has_stable_ref_evidence(value) -> bool:
    if isinstance(value, dict):
        return any(value_has_stable_ref_evidence(item) for item in value.values())
    if isinstance(value, list):
        return any(value_has_stable_ref_evidence(item) for item in value)
    if isinstance(value, str):
        return value_has_material_evidence(value) and not is_summary_ref(value)
    return value_has_material_evidence(value)


def is_vmp_metadata_arg_field(key: str) -> bool:
    return (
        key in VMP_METADATA_ARG_FIELDS
        or key.endswith("_id")
        or key.endswith("_length")
        or key.endswith("_offset")
        or key.endswith("_size")
    )


def value_has_vmp_arg_material_evidence(value) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            if is_preview_field(key_text) or is_redaction_field(key_text):
                continue
            if is_ref_field(key_text):
                if value_has_stable_ref_evidence(item):
                    return True
                continue
            if is_vmp_metadata_arg_field(key_text):
                continue
            if value_has_vmp_arg_material_evidence(item):
                return True
        return False
    if isinstance(value, list):
        return any(value_has_vmp_arg_material_evidence(item) for item in value)
    return value_has_material_evidence(value)


def first_arg(event: dict) -> dict:
    args = event.get("args", [])
    if isinstance(args, list) and args and isinstance(args[0], dict):
        return args[0]
    return {}


def query_keys_from_url(url: str) -> set[str]:
    return set(parse_qs(urlparse(url).query, keep_blank_values=True))


def header_names_from_arg(arg: dict) -> set[str]:
    headers = arg.get("headers", [])
    if not isinstance(headers, list):
        return set()
    return {
        str(header.get("name", "")).lower()
        for header in headers
        if isinstance(header, dict) and header.get("name")
    }


def header_value_names_from_arg(arg: dict) -> set[str]:
    headers = arg.get("headers", [])
    if not isinstance(headers, list):
        return set()
    return {
        str(header.get("name", "")).lower()
        for header in headers
        if (
            isinstance(header, dict)
            and header.get("name")
            and value_has_material_evidence(header.get("value"))
        )
    }


def complete_header_value_names_from_arg(arg: dict) -> set[str]:
    headers = arg.get("headers", [])
    if not isinstance(headers, list):
        return set()
    complete_names = set()
    for header in headers:
        if not isinstance(header, dict) or not header.get("name"):
            continue
        if (
            value_has_material_evidence(header.get("value"))
            and value_has_material_evidence(header.get("name_length"))
            and value_has_material_evidence(header.get("value_length"))
        ):
            complete_names.add(str(header.get("name", "")).lower())
    return complete_names


def text_contains_signature_param(text: str, param: str) -> bool:
    return (
        param in text
        or f"{param}=" in text
        or f"{param}:" in text
        or f'"{param}"' in text
        or f"'{param}'" in text
    )


def arg_mentions_signature_param(
    arg: dict, param: str, *, include_preview: bool = True
) -> bool:
    if str(arg.get("name", "")) == param:
        return True
    if str(arg.get("key", "")) == param:
        return True
    return any(
        text_contains_signature_param(text, param)
        for text in iter_string_values(arg, include_preview=include_preview)
    )


def has_material_ref_for_field(container: dict, field: str) -> bool:
    for ref_field in (f"{field}_ref", f"{field}_refs", "ref"):
        if ref_field in container and value_has_material_evidence(container[ref_field]):
            return True
    return False


def has_signature_value_ref(container: dict) -> bool:
    for field in (
        "value_ref",
        "normalized_value_ref",
        "serialized_ref",
        "result_ref",
        "result_value_refs",
        "href_ref",
        "search_ref",
        "url_ref",
        "body_ref",
    ):
        if field in container and value_has_material_evidence(container[field]):
            return True
    return False


def arg_mentions_signature_param_with_ref(arg, param: str) -> bool:
    if isinstance(arg, dict):
        if str(arg.get("name", "")) == param or str(arg.get("key", "")) == param:
            return has_signature_value_ref(arg)
        for key, item in arg.items():
            key_text = str(key)
            if is_preview_field(key_text):
                continue
            if (
                isinstance(item, str)
                and text_contains_signature_param(item, param)
                and has_material_ref_for_field(arg, key_text)
            ):
                return True
            if arg_mentions_signature_param_with_ref(item, param):
                return True
        return False
    if isinstance(arg, list):
        return any(arg_mentions_signature_param_with_ref(item, param) for item in arg)
    return False


def arg_carries_signature_param(arg: dict, param: str) -> bool:
    url = str(arg.get("url", "") or arg.get("href", ""))
    if url and param in query_keys_from_url(url):
        return True
    header_names = header_names_from_arg(arg)
    if param.lower() in header_names:
        return True
    return arg_mentions_signature_param(arg, param)


def is_business_api_url(url: str) -> bool:
    return urlparse(url).path == BUSINESS_API_ENDPOINT_PATH


def has_stack(event: dict) -> bool:
    return bool(event.get("stack"))


def require_keys(label: str, observed: set[str], required: set[str], missing: list[str]) -> None:
    absent = sorted(required - observed)
    if absent:
        missing.append(f"{label}: {', '.join(absent)}")


def header_source_has_value_material(arg: dict) -> bool:
    return value_has_material_evidence(arg.get("value")) and has_signature_value_ref(arg)


def url_param_source_has_value_material(arg: dict) -> bool:
    return value_has_material_evidence(arg.get("value")) and has_signature_value_ref(arg)


def full_url_source_has_material_refs(arg: dict) -> bool:
    return (
        value_has_material_evidence(arg.get("href"))
        and has_material_ref_for_field(arg, "value")
        and has_material_ref_for_field(arg, "search")
        and has_material_ref_for_field(arg, "href")
    )


def xhr_send_has_body_material(arg: dict) -> bool:
    return (
        value_has_material_evidence(arg.get("body"))
        and has_material_ref_for_field(arg, "body")
    )


def xhr_send_has_material_evidence(
    arg: dict,
    expected_network_correlation_key: object | None,
) -> bool:
    if (
        str(arg.get("method", "")).upper() != "POST"
        or not is_business_api_url(str(arg.get("url", "")))
        or not value_has_material_evidence(arg.get("xhr_id"))
        or not value_has_material_evidence(arg.get("network_correlation_key"))
        or not value_has_material_evidence(arg.get("form_data_id"))
        or not value_has_material_evidence(arg.get("body_search_params_id"))
        or not value_has_material_evidence(arg.get("body_type"))
        or not value_has_material_evidence(arg.get("body_array_buffer_id"))
        or not value_has_material_evidence(arg.get("body_typed_array_id"))
        or not value_has_material_evidence(arg.get("body_byte_offset"))
        or not value_has_material_evidence(arg.get("body_size"))
        or not has_material_ref_for_field(arg, "url")
        or not xhr_send_has_body_material(arg)
    ):
        return False
    if expected_network_correlation_key is None:
        return True
    return arg.get("network_correlation_key") == expected_network_correlation_key


def xhr_response_text_has_material_evidence(
    arg: dict,
    expected_network_correlation_key: object | None,
) -> bool:
    if (
        not is_business_api_url(str(arg.get("url", "")))
        or not value_has_material_evidence(arg.get("xhr_id"))
        or not value_has_material_evidence(arg.get("network_correlation_key"))
        or not value_has_material_evidence(arg.get("status"))
        or not value_has_material_evidence(arg.get("value"))
        or not value_has_material_evidence(arg.get("value_length"))
        or not has_material_ref_for_field(arg, "url")
        or not has_material_ref_for_field(arg, "value")
    ):
        return False
    if expected_network_correlation_key is None:
        return True
    return arg.get("network_correlation_key") == expected_network_correlation_key


def upload_body_has_material_evidence(upload_body: dict) -> bool:
    return (
        value_has_material_evidence(upload_body.get("body_hex"))
        or value_has_material_evidence(upload_body.get("body_sha256"))
        or (
            value_has_material_evidence(upload_body.get("body"))
            and has_material_ref_for_field(upload_body, "body")
        )
    )


def body_json_has_material_evidence(arg: dict) -> bool:
    return (
        value_has_material_evidence(arg.get("result"))
        and value_has_material_evidence(arg.get("result_length"))
        and has_material_ref_for_field(arg, "result")
    )


def response_status_has_material_evidence(arg: dict) -> bool:
    return (
        value_has_material_evidence(arg.get("response_id"))
        and value_has_material_evidence(arg.get("status"))
        and has_material_ref_for_field(arg, "status")
    )


def response_url_has_material_evidence(arg: dict) -> bool:
    return (
        value_has_material_evidence(arg.get("response_id"))
        and value_has_material_evidence(arg.get("url"))
        and has_material_ref_for_field(arg, "url")
    )


def response_headers_has_object_link(arg: dict) -> bool:
    return (
        value_has_material_evidence(arg.get("response_id"))
        and value_has_material_evidence(arg.get("headers_id"))
    )


def request_headers_has_object_link(arg: dict) -> bool:
    return (
        str(arg.get("method", "")).upper() == "GET"
        and is_business_api_url(str(arg.get("url", "")))
        and value_has_material_evidence(arg.get("headers_id"))
        and value_has_material_evidence(arg.get("network_correlation_key"))
        and has_material_ref_for_field(arg, "method")
        and has_material_ref_for_field(arg, "url")
    )


def request_constructor_has_material_evidence(
    arg: dict,
    expected_network_correlation_key: object | None,
) -> bool:
    if (
        str(arg.get("method", "")).upper() != "GET"
        or not is_business_api_url(str(arg.get("url", "")))
        or not value_has_material_evidence(arg.get("input_type"))
        or not value_has_material_evidence(arg.get("headers_id"))
        or not value_has_material_evidence(arg.get("has_init"))
        or not value_has_material_evidence(arg.get("has_body"))
        or not value_has_material_evidence(arg.get("body_byte_length"))
        or not value_has_material_evidence(arg.get("network_correlation_key"))
        or not has_material_ref_for_field(arg, "url")
    ):
        return False
    if expected_network_correlation_key is None:
        return True
    return arg.get("network_correlation_key") == expected_network_correlation_key


def request_url_get_has_material_evidence(
    arg: dict,
    expected_network_correlation_key: object | None,
) -> bool:
    if (
        str(arg.get("method", "")).upper() != "GET"
        or not is_business_api_url(str(arg.get("url", "")))
        or not value_has_material_evidence(arg.get("network_correlation_key"))
        or not has_material_ref_for_field(arg, "method")
        or not has_material_ref_for_field(arg, "url")
    ):
        return False
    if expected_network_correlation_key is None:
        return True
    return arg.get("network_correlation_key") == expected_network_correlation_key


def fetch_call_has_material_evidence(
    arg: dict,
    expected_network_correlation_key: object | None,
) -> bool:
    if (
        str(arg.get("method", "")).upper() != "GET"
        or not is_business_api_url(str(arg.get("url", "")))
        or not value_has_material_evidence(arg.get("headers_id"))
        or not value_has_material_evidence(arg.get("has_body"))
        or not value_has_material_evidence(arg.get("body_byte_length"))
        or not value_has_material_evidence(arg.get("network_correlation_key"))
        or not has_material_ref_for_field(arg, "url")
    ):
        return False
    if expected_network_correlation_key is None:
        return True
    return arg.get("network_correlation_key") == expected_network_correlation_key


def xhr_open_has_material_evidence(
    arg: dict,
    expected_network_correlation_key: object | None,
) -> bool:
    if (
        str(arg.get("method", "")).upper() != "POST"
        or not is_business_api_url(str(arg.get("url", "")))
        or not value_has_material_evidence(arg.get("async"))
        or not value_has_material_evidence(arg.get("network_correlation_key"))
        or not has_material_ref_for_field(arg, "url")
    ):
        return False
    if expected_network_correlation_key is None:
        return True
    return arg.get("network_correlation_key") == expected_network_correlation_key


def request_header_get_has_material_evidence(
    arg: dict,
    request_header_ids: set[str],
    header_name: str,
) -> bool:
    return (
        str(arg.get("headers_id")) in request_header_ids
        and str(arg.get("name", "")).lower() == header_name
        and arg.get("found") is not False
        and value_has_material_evidence(arg.get("name_length"))
        and value_has_material_evidence(arg.get("result"))
        and value_has_material_evidence(arg.get("result_length"))
        and has_material_ref_for_field(arg, "name")
        and has_material_ref_for_field(arg, "result")
    )


def response_header_get_has_material_evidence(
    arg: dict,
    response_header_ids: set[str],
    header_name: str,
) -> bool:
    return (
        str(arg.get("headers_id")) in response_header_ids
        and str(arg.get("name", "")).lower() == header_name
        and arg.get("found") is not False
        and value_has_material_evidence(arg.get("name_length"))
        and value_has_material_evidence(arg.get("result"))
        and value_has_material_evidence(arg.get("result_length"))
        and has_material_ref_for_field(arg, "name")
        and has_material_ref_for_field(arg, "result")
    )


def response_header_iteration_has_material_evidence(
    arg: dict,
    response_header_ids: set[str],
    header_name: str,
) -> bool:
    return (
        str(arg.get("headers_id")) in response_header_ids
        and str(arg.get("name", "")).lower() == header_name
        and value_has_material_evidence(arg.get("iteration_index"))
        and value_has_material_evidence(arg.get("name_length"))
        and value_has_material_evidence(arg.get("value"))
        and value_has_material_evidence(arg.get("value_length"))
        and has_material_ref_for_field(arg, "name")
        and has_material_ref_for_field(arg, "value")
    )


def validate_business_api_item_list(events: list[dict]) -> None:
    missing: list[str] = []

    network_events = [
        event
        for event in events
        if event.get("api") == "BrowserNetwork.request"
        and is_business_api_url(str(first_arg(event).get("url", "")))
    ]
    get_network = next((event for event in network_events if first_arg(event).get("method") == "GET"), None)
    post_network = next((event for event in network_events if first_arg(event).get("method") == "POST"), None)
    if get_network is None:
        missing.append("BrowserNetwork.request GET /api/recommend/item_list/")
    if post_network is None:
        missing.append("BrowserNetwork.request POST /api/recommend/item_list/")

    if get_network is not None:
        get_arg = first_arg(get_network)
        require_keys(
            "GET query fields",
            query_keys_from_url(str(get_arg.get("url", ""))),
            BUSINESS_API_REQUIRED_GET_QUERY_KEYS,
            missing,
        )
        require_keys(
            "GET request headers",
            header_names_from_arg(get_arg),
            BUSINESS_API_REQUIRED_FETCH_HEADER_NAMES | BUSINESS_API_REQUIRED_BROWSER_HEADER_NAMES,
            missing,
        )
        require_keys(
            "GET request header values",
            header_value_names_from_arg(get_arg),
            BUSINESS_API_REQUIRED_FETCH_HEADER_NAMES | BUSINESS_API_REQUIRED_BROWSER_HEADER_NAMES,
            missing,
        )
        require_keys(
            "GET complete request header values",
            complete_header_value_names_from_arg(get_arg),
            BUSINESS_API_REQUIRED_FETCH_HEADER_NAMES | BUSINESS_API_REQUIRED_BROWSER_HEADER_NAMES,
            missing,
        )
        if not get_arg.get("network_correlation_key"):
            missing.append("GET network_correlation_key")

    get_network_correlation_key = (
        first_arg(get_network).get("network_correlation_key")
        if get_network is not None
        else None
    )
    if not any(
        event.get("api") == "Request.constructor"
        and has_stack(event)
        and request_constructor_has_material_evidence(
            first_arg(event),
            get_network_correlation_key,
        )
        for event in events
    ):
        missing.append("GET Request.constructor material evidence")

    if not any(
        event.get("api") == "Request.url.get"
        and request_url_get_has_material_evidence(
            first_arg(event),
            get_network_correlation_key,
        )
        for event in events
    ):
        missing.append("GET Request.url.get material evidence")

    if not any(
        event.get("api") == "fetch"
        and has_stack(event)
        and fetch_call_has_material_evidence(
            first_arg(event),
            get_network_correlation_key,
        )
        for event in events
    ):
        missing.append("GET fetch call material evidence")

    if not any(
        event.get("api") == "Request.headers.get"
        and request_headers_has_object_link(first_arg(event))
        for event in events
    ):
        missing.append("GET Request.headers.get object link")

    request_header_ids = {
        str(first_arg(event).get("headers_id"))
        for event in events
        if event.get("api") == "Request.headers.get"
        and request_headers_has_object_link(first_arg(event))
    }
    request_header_material_names = {
        str(first_arg(event).get("name", "")).lower()
        for event in events
        if event.get("api") == "Headers.get"
        and request_header_get_has_material_evidence(
            first_arg(event),
            request_header_ids,
            str(first_arg(event).get("name", "")).lower(),
        )
    }
    for header_name in sorted(BUSINESS_API_REQUIRED_FETCH_HEADER_NAMES - request_header_material_names):
        missing.append(f"GET Request Headers.get {header_name} material evidence")

    if post_network is not None:
        post_arg = first_arg(post_network)
        require_keys(
            "POST query fields",
            query_keys_from_url(str(post_arg.get("url", ""))),
            BUSINESS_API_REQUIRED_XHR_QUERY_KEYS,
            missing,
        )
        require_keys(
            "POST request headers",
            header_names_from_arg(post_arg),
            BUSINESS_API_REQUIRED_XHR_HEADER_NAMES | BUSINESS_API_REQUIRED_BROWSER_HEADER_NAMES,
            missing,
        )
        require_keys(
            "POST request header values",
            header_value_names_from_arg(post_arg),
            BUSINESS_API_REQUIRED_XHR_HEADER_NAMES | BUSINESS_API_REQUIRED_BROWSER_HEADER_NAMES,
            missing,
        )
        require_keys(
            "POST complete request header values",
            complete_header_value_names_from_arg(post_arg),
            BUSINESS_API_REQUIRED_XHR_HEADER_NAMES | BUSINESS_API_REQUIRED_BROWSER_HEADER_NAMES,
            missing,
        )
        upload_body = post_arg.get("upload_body")
        if not isinstance(upload_body, dict) or not upload_body.get("total_bytes"):
            missing.append("POST upload_body.total_bytes")
        elif not upload_body_has_material_evidence(upload_body):
            missing.append("POST upload_body material evidence")
        if not post_arg.get("network_correlation_key"):
            missing.append("POST network_correlation_key")

    if not any(
        event.get("api") == "Body.json"
        and body_json_has_material_evidence(first_arg(event))
        for event in events
    ):
        missing.append("fetch response Body.json material evidence")

    if not any(
        event.get("api") == "Response.status.get"
        and response_status_has_material_evidence(first_arg(event))
        for event in events
    ):
        missing.append("fetch response Response.status.get material evidence")

    if not any(
        event.get("api") == "Response.url.get"
        and response_url_has_material_evidence(first_arg(event))
        for event in events
    ):
        missing.append("fetch response Response.url.get material evidence")

    if not any(
        event.get("api") == "Response.headers.get"
        and response_headers_has_object_link(first_arg(event))
        for event in events
    ):
        missing.append("fetch response Response.headers.get object link")

    response_header_ids = {
        str(first_arg(event).get("headers_id"))
        for event in events
        if event.get("api") == "Response.headers.get"
        and response_headers_has_object_link(first_arg(event))
    }
    response_header_material_names = {
        str(first_arg(event).get("name", "")).lower()
        for event in events
        if event.get("api") == "Headers.get"
        and response_header_get_has_material_evidence(
            first_arg(event),
            response_header_ids,
            str(first_arg(event).get("name", "")).lower(),
        )
    }
    for header_name in sorted(BUSINESS_API_REQUIRED_RESPONSE_HEADER_NAMES - response_header_material_names):
        missing.append(f"fetch response Headers.get {header_name} material evidence")

    response_header_iteration_material_names = {
        str(first_arg(event).get("name", "")).lower()
        for event in events
        if event.get("api") == "Headers.iterator.next"
        and response_header_iteration_has_material_evidence(
            first_arg(event),
            response_header_ids,
            str(first_arg(event).get("name", "")).lower(),
        )
    }
    for header_name in sorted(
        BUSINESS_API_REQUIRED_RESPONSE_HEADER_NAMES - response_header_iteration_material_names
    ):
        missing.append(f"fetch response Headers.iterator.next {header_name} material evidence")

    url_param_sources = {
        str(first_arg(event).get("name"))
        for event in events
        if event.get("api") == "URLSearchParams.set" and has_stack(event)
    }
    require_keys(
        "URLSearchParams.set source fields",
        url_param_sources,
        BUSINESS_API_REQUIRED_GET_QUERY_KEYS | BUSINESS_API_REQUIRED_XHR_QUERY_KEYS,
        missing,
    )
    url_param_source_material_refs = {
        str(first_arg(event).get("name"))
        for event in events
        if event.get("api") == "URLSearchParams.set"
        and has_stack(event)
        and url_param_source_has_value_material(first_arg(event))
    }
    require_keys(
        "URLSearchParams.set source material refs",
        url_param_source_material_refs,
        BUSINESS_API_REQUIRED_GET_QUERY_KEYS | BUSINESS_API_REQUIRED_XHR_QUERY_KEYS,
        missing,
    )

    if not any(
        event.get("api") == "URL.search.set"
        and has_stack(event)
        and is_business_api_url(str(first_arg(event).get("href", "")))
        and BUSINESS_API_REQUIRED_GET_QUERY_KEYS <= query_keys_from_url(str(first_arg(event).get("href", "")))
        for event in events
    ):
        missing.append("URL.search.set source for full GET item_list query")

    if not any(
        event.get("api") == "URL.search.set"
        and has_stack(event)
        and is_business_api_url(str(first_arg(event).get("href", "")))
        and BUSINESS_API_REQUIRED_GET_QUERY_KEYS <= query_keys_from_url(str(first_arg(event).get("href", "")))
        and full_url_source_has_material_refs(first_arg(event))
        for event in events
    ):
        missing.append("URL.search.set material refs for full GET item_list query")

    fetch_header_sources = {
        str(first_arg(event).get("name", "")).lower()
        for event in events
        if event.get("api") in {"Headers.set", "Headers.append"} and has_stack(event)
    }
    require_keys(
        "fetch header source fields",
        fetch_header_sources,
        BUSINESS_API_REQUIRED_FETCH_HEADER_NAMES,
        missing,
    )
    fetch_header_source_material_refs = {
        str(first_arg(event).get("name", "")).lower()
        for event in events
        if event.get("api") in {"Headers.set", "Headers.append"}
        and has_stack(event)
        and header_source_has_value_material(first_arg(event))
    }
    require_keys(
        "fetch header source material refs",
        fetch_header_source_material_refs,
        BUSINESS_API_REQUIRED_FETCH_HEADER_NAMES,
        missing,
    )

    xhr_header_sources = {
        str(first_arg(event).get("name", "")).lower()
        for event in events
        if event.get("api") == "XMLHttpRequest.setRequestHeader" and has_stack(event)
    }
    require_keys(
        "XHR header source fields",
        xhr_header_sources,
        BUSINESS_API_REQUIRED_XHR_HEADER_NAMES,
        missing,
    )
    xhr_header_source_material_refs = {
        str(first_arg(event).get("name", "")).lower()
        for event in events
        if event.get("api") == "XMLHttpRequest.setRequestHeader"
        and has_stack(event)
        and header_source_has_value_material(first_arg(event))
    }
    require_keys(
        "XHR header source material refs",
        xhr_header_source_material_refs,
        BUSINESS_API_REQUIRED_XHR_HEADER_NAMES,
        missing,
    )

    get_key = first_arg(get_network).get("network_correlation_key") if get_network is not None else None
    if get_key and not any(
        event.get("api") in {"Request.constructor", "fetch"}
        and first_arg(event).get("network_correlation_key") == get_key
        and has_stack(event)
        for event in events
    ):
        missing.append("GET Request.constructor/fetch source correlation")

    post_key = first_arg(post_network).get("network_correlation_key") if post_network is not None else None
    if post_key:
        if not any(
            event.get("api") == "XMLHttpRequest.open"
            and has_stack(event)
            and xhr_open_has_material_evidence(first_arg(event), post_key)
            for event in events
        ):
            missing.append("POST XMLHttpRequest.open material evidence")
        if not any(
            event.get("api") == "XMLHttpRequest.setRequestHeader"
            and first_arg(event).get("network_correlation_key") == post_key
            and has_stack(event)
            for event in events
        ):
            missing.append("POST XMLHttpRequest.setRequestHeader source correlation")
        if not any(
            event.get("api") == "XMLHttpRequest.send"
            and first_arg(event).get("network_correlation_key") == post_key
            and first_arg(event).get("body_size")
            and has_stack(event)
            for event in events
        ):
            missing.append("POST XMLHttpRequest.send body source correlation")
        if not any(
            event.get("api") == "XMLHttpRequest.send"
            and has_stack(event)
            and xhr_send_has_material_evidence(first_arg(event), post_key)
            for event in events
        ):
            missing.append("POST XMLHttpRequest.send material evidence")
        if not any(
            event.get("api") == "XMLHttpRequest.send"
            and first_arg(event).get("network_correlation_key") == post_key
            and first_arg(event).get("body_size")
            and xhr_send_has_body_material(first_arg(event))
            and has_stack(event)
            for event in events
        ):
            missing.append("POST XMLHttpRequest.send body material refs")
        if not any(
            event.get("api") == "XMLHttpRequest.responseText"
            and has_stack(event)
            and xhr_response_text_has_material_evidence(first_arg(event), post_key)
            for event in events
        ):
            missing.append("POST XMLHttpRequest.responseText material evidence")

    if missing:
        raise TraceValidationError(
            "Missing business API item_list evidence: " + "; ".join(missing)
        )


def validate_signature_param_materialization(events: list[dict], params: Iterable[str]) -> None:
    missing: list[str] = []
    for param in params:
        has_request_carrier = any(
            event.get("api") in SIGNATURE_PARAM_CARRIER_APIS
            and arg_carries_signature_param(first_arg(event), param)
            for event in events
        )
        if not has_request_carrier:
            missing.append(f"{param} signed request carrier")

        has_runtime_materialization = any(
            event.get("api") in SIGNATURE_PARAM_MATERIALIZATION_APIS
            and arg_mentions_signature_param_with_ref(first_arg(event), param)
            for event in events
        )
        if not has_runtime_materialization:
            missing.append(f"{param} runtime materialization")

    if missing:
        raise TraceValidationError(
            "Missing signature parameter materialization evidence: "
            + "; ".join(missing)
        )


def validate_complete_values(events: list[dict]) -> None:
    partial: list[str] = []
    for index, event in enumerate(events, start=1):
        api = str(event.get("api", "<unknown>"))
        if event.get("truncated") is True:
            partial.append(f"truncated event {index}: {api}")
        for kind, path in iter_partial_value_evidence(event):
            partial.append(f"{kind} event {index}: {path}")

    if partial:
        raise TraceValidationError(
            "Partial value evidence found while complete values are required: "
            + "; ".join(partial)
        )


def validate_material_refs(events: list[dict]) -> None:
    summary_refs: list[str] = []
    opaque_refs: list[str] = []
    for index, event in enumerate(events, start=1):
        for path in iter_summary_ref_values(event):
            summary_refs.append(f"summary ref event {index}: {path}")
        for path in iter_opaque_refs_without_raw_material(event):
            opaque_refs.append(f"opaque ref event {index}: {path}")

    material_ref_failures = summary_refs + opaque_refs
    if material_ref_failures:
        raise TraceValidationError(
            "Non-material refs found while material refs are required: "
            + "; ".join(material_ref_failures)
        )


def event_has_vmp_family_evidence(event: dict) -> bool:
    return (
        value_has_vmp_arg_material_evidence(event.get("args", []))
        or value_has_material_evidence(event.get("result"))
        or value_has_material_evidence(event.get("error"))
    )


def validate_trace(
    path: Path,
    expected: Iterable[str] = DEFAULT_EXPECTED_APIS,
    schema_version: int | None = None,
    require_stack_for: Iterable[str] = (),
    require_context_for: Iterable[str] = (),
    require_vmp_families: Iterable[str] = (),
    require_arg_fields: Iterable[str] = (),
    require_vmp_next_hook_fields: bool = False,
    require_business_api_item_list: bool = False,
    require_signature_param_materialization: Iterable[str] = (),
    require_complete_values: bool = False,
    require_vmp_family_evidence: bool = False,
    require_material_refs: bool = False,
) -> None:
    events = load_events(path)
    if schema_version is not None:
        if schema_version not in (1, 2):
            raise TraceValidationError(f"Unsupported schema version: {schema_version}")
        for index, event in enumerate(events, start=1):
            if schema_version == 1:
                validate_schema_v1_event(event, index)
            else:
                validate_schema_v2_event(event, index)
        validate_global_sequence(events)
        if schema_version == 2:
            validate_causality(events)

    if require_context_for:
        validate_context_for_apis(events, require_context_for)

    if require_complete_values:
        validate_complete_values(events)

    if require_material_refs:
        validate_material_refs(events)

    seen = {event.get("api") for event in events}
    missing = [api for api in expected if api not in seen]
    if missing:
        raise TraceValidationError("Missing expected APIs: " + ", ".join(missing))

    required_stack_apis = set(require_stack_for)
    if required_stack_apis:
        missing_stack = []
        for api in required_stack_apis:
            matching_events = [event for event in events if event.get("api") == api]
            if matching_events and not any(event.get("stack") for event in matching_events):
                missing_stack.append(api)
        if missing_stack:
            raise TraceValidationError(
                "Expected non-empty stack for APIs: " + ", ".join(missing_stack)
            )

    required_vmp_families = set(require_vmp_families)
    if required_vmp_families or require_vmp_family_evidence:
        unknown_families = sorted(required_vmp_families - set(VMP_FAMILIES))
        if unknown_families:
            raise TraceValidationError("Unknown VMP families: " + ", ".join(unknown_families))
        vmp_family_events: dict[str, list[dict]] = {}
        for event in events:
            api = event.get("api")
            if api in VMP_API_FAMILY:
                vmp_family_events.setdefault(VMP_API_FAMILY[api], []).append(event)
        observed_families = set(vmp_family_events)
        missing_families = [family for family in VMP_FAMILIES if family in required_vmp_families and family not in observed_families]
        if missing_families:
            raise TraceValidationError("Missing expected VMP families: " + ", ".join(missing_families))
        if require_vmp_family_evidence:
            if not vmp_family_events:
                raise TraceValidationError("Missing VMP family evidence: no VMP family events observed")
            observed_evidence_families = {
                family
                for family, family_events in vmp_family_events.items()
                if any(event_has_vmp_family_evidence(event) for event in family_events)
            }
            evidence_scope = required_vmp_families or observed_families
            missing_evidence_families = [
                family
                for family in VMP_FAMILIES
                if family in evidence_scope
                and family not in observed_evidence_families
            ]
            if missing_evidence_families:
                raise TraceValidationError(
                    "Missing VMP family evidence: "
                    + ", ".join(missing_evidence_families)
                )

    required_arg_field_specs = list(require_arg_fields)
    if require_vmp_next_hook_fields:
        required_arg_field_specs.extend(VMP_NEXT_HOOK_REQUIRED_ARG_FIELDS)

    required_arg_fields = [parse_required_arg_field(spec) for spec in required_arg_field_specs]
    observed_required_arg_fields = [
        parse_required_arg_field(spec)
        for spec in (VMP_NEXT_HOOK_REQUIRED_OBSERVED_ARG_FIELDS if require_vmp_next_hook_fields else [])
    ]
    missing_arg_fields = []
    if required_arg_fields:
        for api, field in required_arg_fields:
            matching_events = [event for event in events if event.get("api") == api]
            if matching_events and not any(value_has_field(event.get("args", []), field) for event in matching_events):
                missing_arg_fields.append(f"{api}:{field}")
            elif not matching_events:
                missing_arg_fields.append(f"{api}:{field}")
    missing_observed_arg_fields = []
    if observed_required_arg_fields:
        for api, field in observed_required_arg_fields:
            matching_events = [event for event in events if event.get("api") == api]
            if matching_events and not any(value_has_key(event.get("args", []), field) for event in matching_events):
                missing_observed_arg_fields.append(f"{api}:{field}")
    if require_vmp_next_hook_fields:
        missing_observed_arg_fields.extend(missing_form_data_branch_fields(events))
    if missing_arg_fields or missing_observed_arg_fields:
        parts = []
        if missing_arg_fields:
            parts.append("Expected arg fields not found: " + ", ".join(missing_arg_fields))
        if missing_observed_arg_fields:
            parts.append("Expected observed API arg fields not found: " + ", ".join(missing_observed_arg_fields))
        raise TraceValidationError("; ".join(parts))

    if require_business_api_item_list:
        validate_business_api_item_list(events)

    required_signature_params = list(require_signature_param_materialization)
    if required_signature_params:
        validate_signature_param_materialization(events, required_signature_params)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=sorted(PROFILE_EXPECTED_APIS), default=None)
    parser.add_argument("--schema-version", type=int, choices=[1, 2], default=None)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--expect", action="append", default=[])
    parser.add_argument("--require-stack-for", action="append", default=[])
    parser.add_argument(
        "--require-context-for",
        action="append",
        default=[],
        metavar="API",
        help="require API to be observed and every matching event to have non-empty frame_url and origin",
    )
    parser.add_argument("--require-vmp-family", choices=VMP_FAMILIES, action="append", default=[])
    parser.add_argument(
        "--require-arg-field",
        action="append",
        default=[],
        help="require a material API args field, formatted as API:field; may be repeated",
    )
    parser.add_argument(
        "--require-vmp-next-hook-fields",
        action="store_true",
        help="require core VMP boundary result refs used to verify dynamic dispatch and encoded string/int-mix traces",
    )
    parser.add_argument(
        "--require-signature-param-materialization",
        action="append",
        default=[],
        metavar="PARAM",
        help="require PARAM to appear in a signed request and in a non-network runtime materialization event with refs",
    )
    parser.add_argument(
        "--require-complete-values",
        action="store_true",
        help="reject trace events containing truncated, preview-only, or redacted value evidence",
    )
    parser.add_argument(
        "--require-vmp-family-evidence",
        action="store_true",
        help="require observed VMP families to include non-metadata args, result, or error material evidence",
    )
    parser.add_argument(
        "--require-material-refs",
        action="store_true",
        help="reject length-only refs and opaque refs without same-object raw material fields",
    )
    parser.add_argument(
        "--strict-capture",
        action="store_true",
        help=(
            "enable the online reconstruction gate: schema v1, complete values, "
            "material refs, VMP family evidence, and VMP boundary field checks"
        ),
    )
    args = parser.parse_args(argv)

    profile = args.profile
    if args.strict_capture and profile is None and not args.expect:
        profile = "reverse"
    if profile is None and not args.expect:
        profile = "fingerprint"
    expected = expected_apis_for_profile(profile, args.expect)
    schema_version = args.schema_version
    if args.strict_capture and schema_version is None:
        schema_version = 1
    require_vmp_families = list(args.require_vmp_family)
    require_signature_param_materialization = list(args.require_signature_param_materialization)
    if args.strict_capture and profile != "generic-vmp":
        require_vmp_families = merge_required_values(
            require_vmp_families,
            STRICT_CAPTURE_VMP_FAMILIES,
        )
    if args.strict_capture:
        require_signature_param_materialization = merge_required_values(
            require_signature_param_materialization,
            STRICT_CAPTURE_PROFILE_SIGNATURE_PARAMS.get(profile, []),
        )
    require_vmp_next_hook_fields = (
        args.require_vmp_next_hook_fields
        or (args.strict_capture and profile != "generic-vmp")
    )
    try:
        validate_trace(
            args.trace,
            expected=expected,
            schema_version=schema_version,
            require_stack_for=args.require_stack_for,
            require_context_for=args.require_context_for,
            require_vmp_families=require_vmp_families,
            require_arg_fields=args.require_arg_field,
            require_vmp_next_hook_fields=require_vmp_next_hook_fields,
            require_business_api_item_list=profile == "business-api",
            require_signature_param_materialization=require_signature_param_materialization,
            require_complete_values=args.require_complete_values or args.strict_capture,
            require_vmp_family_evidence=args.require_vmp_family_evidence or args.strict_capture,
            require_material_refs=args.require_material_refs or args.strict_capture,
        )
    except (TraceValidationError, OSError, UnicodeDecodeError) as exc:
        print(f"FAIL: {exc}")
        return 1
    print(f"PASS: {args.trace}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
