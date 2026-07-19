import Java from 'frida-java-bridge';

/**
 * @typedef {{ name: string, value: string }} Field
 * @typedef {{ methods: Record<string, Field[]>, strings: Record<string, Field[]> }} Reflected
 */

/** @param {Reflected} data */
function extractValues(data) {

  const lookups = { ...data.strings, ...data.methods };
  for (const [className, fields] of Object.entries(lookups)) {
    const JavaClass = Java.use(className);

    for (const field of fields) {
      const fieldRef = JavaClass[field.name];
      field.value = fieldRef.value.toString();
    }
  }

  return data;
}

rpc.exports = {
  extractValues: function (data) {
    return new Promise(function (resolve, reject) {
      Java.perform(function () {
        try {
          resolve(extractValues(data));
        } catch (e) {
          reject(e);
        }
      });
    });
  }
};
