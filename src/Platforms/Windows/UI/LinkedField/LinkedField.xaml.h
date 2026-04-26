#pragma once

#include "LinkedField.g.h"

namespace winrt::WindowsUI::implementation
{
    struct LinkedField : LinkedFieldT<LinkedField>
    {
        LinkedField()
        {
            // Xaml objects should not call InitializeComponent during construction.
            // See https://github.com/microsoft/cppwinrt/tree/master/nuget#initializecomponent
        }

        winrt::hstring Title();
        void Title(winrt::hstring value);

        winrt::hstring Value();
        void Value(winrt::hstring value);
    };
}

namespace winrt::WindowsUI::factory_implementation
{
    struct LinkedField : LinkedFieldT<LinkedField, implementation::LinkedField>
    {
    };
}
